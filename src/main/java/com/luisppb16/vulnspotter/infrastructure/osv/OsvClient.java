/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.osv;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.util.io.HttpRequests;
import com.luisppb16.vulnspotter.domain.model.OsvBatchQuery;
import com.luisppb16.vulnspotter.domain.model.OsvBatchResponse;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.domain.model.OsvQuery;
import com.luisppb16.vulnspotter.domain.model.OsvResponse;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.domain.model.PackageKey;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import com.luisppb16.vulnspotter.util.Json;
import java.io.IOException;
import java.io.Serial;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.IntStream;

/**
 * Client for interacting with the OSV.dev API to check for vulnerabilities. Uses IntelliJ's
 * HttpRequests for network calls to integrate properly with IDE's proxy and avoid macOS keychain
 * popups.
 *
 * <p>The {@code /v1/querybatch} endpoint only returns minimal records (id + modified), so after the
 * batch lookup every distinct vulnerability id is hydrated through {@code /v1/vulns/{id}} (with its
 * own cache) to obtain severity, summary, affected ranges and references.
 *
 * <p>Network failures are propagated as failed futures — they are never silently converted into "no
 * vulnerabilities".
 */
public class OsvClient {

  private static final Logger LOG = Logger.getInstance(OsvClient.class);

  /** OSV rejects batches above 1000 queries. */
  private static final int MAX_BATCH_SIZE = 1000;

  /** Safety bound for paginated results per scan. */
  private static final int MAX_PAGES = 5;

  /**
   * Fail-safe cap on the hydrated-records cache: {@link #hydrate} drops records the batch did not
   * touch once the map grows past it (stamps otherwise keep matched records reused for the whole
   * session, so ids from packages long dropped by the project would accumulate unbounded).
   */
  private static final int MAX_VULN_CACHE_ENTRIES = 5000;

  private static final int HTTP_TIMEOUT_MS = 10000;
  private static final int MAX_ATTEMPTS = 3;
  private static final long RETRY_BACKOFF_MS = 500;

  private final ExecutorService executorService;
  private final ConcurrentHashMap<PackageKey, CacheEntry<OsvResponse>> packageCache =
      new ConcurrentHashMap<>();

  /**
   * Full records by advisory id; freshness is the {@code modified}-stamp revalidation in {@link
   * #hydrate} ({@link #invalidateCache} deliberately keeps them) and only the cap in {@link
   * #hydrate} evicts.
   */
  private final ConcurrentHashMap<String, OsvVulnerability> vulnCache = new ConcurrentHashMap<>();

  public OsvClient() {
    this(Executors.newFixedThreadPool(16));
  }

  public OsvClient(ExecutorService executorService) {
    this.executorService = executorService;
  }

  private static OsvResponse mergeVulns(OsvResponse accumulated, OsvResponse page) {
    if (page == null || page.vulns() == null || page.vulns().isEmpty()) {
      return accumulated;
    }
    if (accumulated == null || accumulated.vulns() == null || accumulated.vulns().isEmpty()) {
      return new OsvResponse(page.vulns());
    }
    // De-duplicate by vulnerability id so a vuln returned on two pages is not shown twice.
    Map<String, OsvVulnerability> byId = new LinkedHashMap<>();
    for (OsvVulnerability v : accumulated.vulns()) {
      if (v.id() != null) {
        byId.put(v.id(), v);
      }
    }
    for (OsvVulnerability v : page.vulns()) {
      if (v.id() != null) {
        byId.putIfAbsent(v.id(), v);
      }
    }
    return new OsvResponse(new ArrayList<>(byId.values()));
  }

  private static IdsToHydrate collectIdStamps(List<OsvResponse> minimalResults) {
    Map<String, String> modifiedById = new LinkedHashMap<>();
    Set<String> unstampedIds = new LinkedHashSet<>();
    for (OsvResponse response : minimalResults) {
      if (response == null || response.vulns() == null) continue;
      for (OsvVulnerability vuln : response.vulns()) {
        if (vuln.id() == null || vuln.id().isBlank()) continue;
        if (vuln.modified() == null || vuln.modified().isBlank()) {
          unstampedIds.add(vuln.id());
        } else {
          modifiedById.put(vuln.id(), vuln.modified());
        }
      }
    }
    // A later page of the same batch may have proven the id's stamp; revalidation then applies.
    unstampedIds.removeAll(modifiedById.keySet());
    return new IdsToHydrate(modifiedById, unstampedIds);
  }

  /** True for failures worth retrying: 5xx, 429, timeouts. 4xx (except 429) fails fast. */
  private static boolean isTransient(IOException e) {
    if (e instanceof HttpRequests.HttpStatusException status) {
      int code = status.getStatusCode();
      return code == 429 || code >= 500;
    }
    return true; // connect/read timeouts and other I/O errors
  }

  private static void sleepBackoff(int attempt) {
    try {
      Thread.sleep(RETRY_BACKOFF_MS * attempt);
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }
  }

  /** Identity of a package answer: name, version and ecosystem as a typed record. */
  private static PackageKey key(OsvPackage pkg) {
    return new PackageKey(pkg.name(), pkg.version(), pkg.ecosystem());
  }

  private static Instant cacheExpiration() {
    int cacheMinutes = VulnSpotterSettings.getInstance().getCacheDurationMinutes();
    return Instant.now().plus(Duration.ofMinutes(cacheMinutes));
  }

  private static OsvResponse emptyToNull(OsvResponse response) {
    if (response == null || response.vulns() == null || response.vulns().isEmpty()) {
      return null;
    }
    return response;
  }

  /** True when the cached full record is exactly what OSV would return now (stamp equality). */
  static boolean canTrustCached(OsvVulnerability cached, String batchModified) {
    return cached != null && batchModified != null && batchModified.equals(cached.modified());
  }

  /**
   * Runs the HTTP call with limited retries for transient failures; the verb-specific request is
   * the only thing the two callers differ in.
   */
  private static String withRetry(HttpCall call) throws IOException {
    IOException lastFailure = null;
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        return call.read();
      } catch (IOException e) {
        if (!isTransient(e)) {
          throw e;
        }
        lastFailure = e;
        if (attempt < MAX_ATTEMPTS) {
          sleepBackoff(attempt);
        }
      }
    }
    throw lastFailure;
  }

  /** Releases the internal thread pool. Called when the owning project service is disposed. */
  public void shutdown() {
    executorService.shutdown();
  }

  /**
   * Discards the cached per-package batch answers so the next scan re-queries OSV.dev's batch
   * endpoint. Hydrated vulnerability records are deliberately kept: {@link #hydrate} revalidates
   * them against the {@code modified} stamp of the fresh batch answer, so unchanged advisories are
   * reused without a per-id GET no matter when they were cached. Thread-safe and cheap (one map
   * clear).
   */
  public void invalidateCache() {
    packageCache.clear();
  }

  /**
   * Batch-checks packages and hydrates each reported vulnerability id into a full OSV record. The
   * returned list preserves the order of {@code packages}; entries without vulnerabilities are
   * {@code null}.
   */
  public CompletableFuture<OsvBatchResponse> checkDependencies(List<OsvPackage> packages) {
    Objects.requireNonNull(packages, "Packages list cannot be null");

    return CompletableFuture.supplyAsync(() -> doCheckDependencies(packages), executorService);
  }

  private OsvBatchResponse doCheckDependencies(List<OsvPackage> packages) {
    Instant exp = cacheExpiration();
    List<OsvResponse> finalResults = new ArrayList<>(Collections.nCopies(packages.size(), null));
    List<OsvQuery> queriesToFetch = new ArrayList<>();
    List<Integer> fetchIndices = new ArrayList<>();

    for (int i = 0; i < packages.size(); i++) {
      OsvPackage pkg = packages.get(i);
      CacheEntry<OsvResponse> entry = packageCache.get(key(pkg));
      if (entry != null && entry.isFresh()) {
        finalResults.set(i, emptyToNull(entry.value));
      } else {
        queriesToFetch.add(new OsvQuery(pkg.version(), pkg));
        fetchIndices.add(i);
      }
    }

    if (queriesToFetch.isEmpty()) {
      return new OsvBatchResponse(finalResults);
    }

    // 1. Batch lookup (minimal records: id + modified), chunked to the OSV batch limit.
    List<OsvResponse> minimalResults = fetchMinimalRecords(queriesToFetch);

    // 2. Hydrate every distinct vulnerability id into a full record (revalidated by "modified").
    Map<String, OsvVulnerability> hydrated = hydrate(collectIdStamps(minimalResults));

    // 3. Rebuild per-package responses with the full records and refresh the cache.
    for (int j = 0; j < fetchIndices.size(); j++) {
      int originalIndex = fetchIndices.get(j);
      OsvResponse minimal = j < minimalResults.size() ? minimalResults.get(j) : null;

      if (minimal == null || minimal.vulns() == null || minimal.vulns().isEmpty()) {
        // Only cache a definitive "no vulnerabilities" when OSV actually answered this query.
        if (j < minimalResults.size()) {
          packageCache.put(
              key(packages.get(originalIndex)), new CacheEntry<>(new OsvResponse(List.of()), exp));
        }
        continue;
      }

      List<OsvVulnerability> fullVulns =
          minimal.vulns().stream()
              .filter(v -> v.id() != null)
              .map(v -> hydrated.getOrDefault(v.id(), v))
              .filter(v -> !v.isWithdrawn())
              .toList();

      OsvResponse full = new OsvResponse(fullVulns);
      finalResults.set(originalIndex, emptyToNull(full));
      packageCache.put(key(packages.get(originalIndex)), new CacheEntry<>(full, exp));
    }

    return new OsvBatchResponse(finalResults);
  }

  /** Runs the querybatch call in chunks, following per-result pagination tokens. */
  private List<OsvResponse> fetchMinimalRecords(List<OsvQuery> queries) {
    List<OsvResponse> results = new ArrayList<>(Collections.nCopies(queries.size(), null));

    for (int start = 0; start < queries.size(); start += MAX_BATCH_SIZE) {
      List<PendingQuery> pending =
          IntStream.rangeClosed(start, Math.min(start + MAX_BATCH_SIZE, queries.size()) - 1)
              .mapToObj(i -> i)
              .map(i -> new PendingQuery(queries.get(i), i))
              .toList();

      for (int page = 0; page < MAX_PAGES && !pending.isEmpty(); page++) {
        OsvBatchResponse batch = postBatch(pending.stream().map(PendingQuery::query).toList());
        List<OsvResponse> batchResults = batch.results();

        List<PendingQuery> nextPending = new ArrayList<>();
        for (int k = 0; k < pending.size(); k++) {
          OsvResponse pageResult = k < batchResults.size() ? batchResults.get(k) : null;
          int globalIndex = pending.get(k).index();
          results.set(globalIndex, mergeVulns(results.get(globalIndex), pageResult));

          if (pageResult != null
              && pageResult.nextPageToken() != null
              && !pageResult.nextPageToken().isBlank()) {
            nextPending.add(
                new PendingQuery(
                    pending.get(k).query().withPageToken(pageResult.nextPageToken()), globalIndex));
          }
        }
        pending = nextPending;
      }
      if (!pending.isEmpty()) {
        LOG.warn(
            "OSV pagination cap reached ("
                + MAX_PAGES
                + " pages) for "
                + pending.size()
                + " package(s); remaining vulnerabilities may not be reported. "
                + "Re-scan to fetch more.");
      }
    }
    return results;
  }

  /** A queued follow-up page: the next-token query and its position in the batch. */
  private record PendingQuery(OsvQuery query, int index) {}

  private OsvBatchResponse postBatch(List<OsvQuery> queries) {
    try {
      String requestBody = Json.MAPPER.writeValueAsString(new OsvBatchQuery(queries));
      String responseBody = postWithRetry(ProjectConstants.OSV_API_BATCH_URL, requestBody);
      if (responseBody == null || responseBody.isEmpty()) {
        throw new OsvClientException("Empty response from OSV batch API", null);
      }
      return Json.MAPPER.readValue(responseBody, OsvBatchResponse.class);
    } catch (IOException e) {
      throw new OsvClientException("OSV batch query failed", e);
    }
  }

  /**
   * Fetches full records for the given ids, using the per-id cache revalidated by the OSV {@code
   * modified} stamp: a cached record whose stamp equals the one just returned by the batch lookup
   * is provably current and is reused without a GET, regardless of when it was cached. Ids without
   * a stamp are fetched fresh. Individual failures degrade to the minimal record instead of failing
   * the whole scan.
   */
  private Map<String, OsvVulnerability> hydrate(IdsToHydrate ids) {
    Map<String, OsvVulnerability> hydrated = new ConcurrentHashMap<>();
    List<CompletableFuture<Void>> tasks = new ArrayList<>();

    for (String id : ids.unstampedIds()) {
      tasks.add(fetchAndCache(id, hydrated));
    }
    for (Map.Entry<String, String> entry : ids.modifiedById().entrySet()) {
      String id = entry.getKey();
      OsvVulnerability cached = vulnCache.get(id);
      if (canTrustCached(cached, entry.getValue())) {
        hydrated.put(id, cached);
        continue;
      }
      tasks.add(fetchAndCache(id, hydrated));
    }

    CompletableFuture.allOf(tasks.toArray(new CompletableFuture<?>[0])).join();
    if (vulnCache.size() > MAX_VULN_CACHE_ENTRIES) {
      // Long-session safety valve; a dropped id is refetched by a later batch that reports it.
      vulnCache.keySet().removeIf(id -> !hydrated.containsKey(id));
    }
    return hydrated;
  }

  private CompletableFuture<Void> fetchAndCache(String id, Map<String, OsvVulnerability> hydrated) {
    return CompletableFuture.runAsync(
        () -> {
          OsvVulnerability full = fetchVulnerability(id);
          if (full != null) {
            hydrated.put(id, full);
            vulnCache.put(id, full);
          }
        },
        executorService);
  }

  private OsvVulnerability fetchVulnerability(String id) {
    String url = ProjectConstants.OSV_API_VULNS_URL + URLEncoder.encode(id, StandardCharsets.UTF_8);
    try {
      String body = getWithRetry(url);
      return Json.MAPPER.readValue(body, OsvVulnerability.class);
    } catch (IOException e) {
      LOG.warn("Failed to hydrate OSV record " + id + "; falling back to minimal data", e);
      return null;
    }
  }

  /** GET with limited retries for transient failures. */
  private String getWithRetry(String url) throws IOException {
    return withRetry(
        () ->
            HttpRequests.request(url)
                .connectTimeout(HTTP_TIMEOUT_MS)
                .readTimeout(HTTP_TIMEOUT_MS)
                .readString());
  }

  /** POST with limited retries for transient failures. */
  private String postWithRetry(String url, String requestBody) throws IOException {
    return withRetry(
        () ->
            HttpRequests.post(url, "application/json")
                .connectTimeout(HTTP_TIMEOUT_MS)
                .readTimeout(HTTP_TIMEOUT_MS)
                .connect(
                    request -> {
                      request.write(requestBody);
                      return request.readString();
                    }));
  }

  /** A blocking HTTP read, expressed the way HttpRequests builds one. */
  @FunctionalInterface
  private interface HttpCall {
    String read() throws IOException;
  }

  /**
   * Hydration input from the batch answer: id → "modified" stamp (insertion-ordered, stable for
   * hydrate), plus the ids whose batch record carries no usable stamp. A missing {@code modified}
   * proves nothing about a cached copy, so unstamped ids are never served from the cache — they are
   * fetched every scan, because omitting them silently degraded those advisories to bare id-only
   * rows that lost severity, summary, ranges, fixed versions and references.
   */
  private record IdsToHydrate(Map<String, String> modifiedById, Set<String> unstampedIds) {}

  /** Signals an OSV API failure; carried by the future so callers can show a real error. */
  public static final class OsvClientException extends RuntimeException {
    @Serial private static final long serialVersionUID = 1L;

    public OsvClientException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  private record CacheEntry<T>(T value, Instant expiration) {

    boolean isFresh() {
      return Instant.now().isBefore(expiration);
    }
  }
}
