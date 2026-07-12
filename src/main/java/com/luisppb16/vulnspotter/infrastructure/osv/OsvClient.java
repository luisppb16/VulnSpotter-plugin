/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.util.io.HttpRequests;
import com.luisppb16.vulnspotter.domain.model.OsvBatchQuery;
import com.luisppb16.vulnspotter.domain.model.OsvBatchResponse;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.domain.model.OsvQuery;
import com.luisppb16.vulnspotter.domain.model.OsvResponse;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
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
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

  private static final int HTTP_TIMEOUT_MS = 10000;
  private static final int MAX_ATTEMPTS = 3;
  private static final long RETRY_BACKOFF_MS = 500;

  private final ObjectMapper objectMapper;
  private final ExecutorService executorService;
  private final ConcurrentHashMap<String, CacheEntry<OsvResponse>> packageCache =
      new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, CacheEntry<OsvVulnerability>> vulnCache =
      new ConcurrentHashMap<>();

  public OsvClient() {
    this(Executors.newFixedThreadPool(16));
  }

  public OsvClient(ExecutorService executorService) {
    this.executorService = executorService;
    this.objectMapper = new ObjectMapper();
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

  private static Set<String> collectIds(List<OsvResponse> minimalResults) {
    Set<String> ids = new LinkedHashSet<>();
    for (OsvResponse response : minimalResults) {
      if (response == null || response.vulns() == null) continue;
      for (OsvVulnerability vuln : response.vulns()) {
        if (vuln.id() != null && !vuln.id().isBlank()) {
          ids.add(vuln.id());
        }
      }
    }
    return ids;
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
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
    }
  }

  private static String cacheKey(OsvPackage pkg) {
    return pkg.ecosystem() + ":" + pkg.name() + ":" + pkg.version();
  }

  private static Instant cacheExpiration() {
    int cacheMinutes =
        VulnSpotterSettings.getInstance() != null
            ? VulnSpotterSettings.getInstance().getCacheDurationMinutes()
            : 60;
    return Instant.now().plus(Duration.ofMinutes(cacheMinutes));
  }

  private static Optional<OsvResponse> toOptionalResponse(OsvResponse response) {
    return Optional.ofNullable(emptyToNull(response));
  }

  private static OsvResponse emptyToNull(OsvResponse response) {
    if (response == null || response.vulns() == null || response.vulns().isEmpty()) {
      return null;
    }
    return response;
  }

  /** Drops withdrawn advisories, preserving the pagination token. */
  private static OsvResponse filterWithdrawn(OsvResponse response) {
    if (response == null || response.vulns() == null) {
      return response;
    }
    List<OsvVulnerability> active =
        response.vulns().stream().filter(v -> !v.isWithdrawn()).toList();
    return new OsvResponse(active, response.nextPageToken());
  }

  /** Releases the internal thread pool. Called when the owning project service is disposed. */
  public void shutdown() {
    executorService.shutdown();
  }

  public CompletableFuture<Optional<OsvResponse>> checkDependency(
      String packageName, String version, String ecosystem) {
    Objects.requireNonNull(packageName, "Package name cannot be null");
    Objects.requireNonNull(version, "Version cannot be null");
    Objects.requireNonNull(ecosystem, "Ecosystem cannot be null");

    String cacheKey = ecosystem + ":" + packageName + ":" + version;
    CacheEntry<OsvResponse> entry = packageCache.get(cacheKey);
    if (entry != null && entry.isFresh()) {
      return CompletableFuture.completedFuture(toOptionalResponse(entry.value));
    }

    return CompletableFuture.supplyAsync(
        () -> {
          try {
            OsvPackage osvPackage = new OsvPackage(packageName, ecosystem, version);
            OsvQuery query = new OsvQuery(version, osvPackage);
            String requestBody = objectMapper.writeValueAsString(query);
            String responseBody = postWithRetry(ProjectConstants.OSV_API_URL, requestBody);

            OsvResponse raw =
                (responseBody == null || responseBody.isEmpty() || "{}".equals(responseBody.trim()))
                    ? new OsvResponse(List.of())
                    : objectMapper.readValue(responseBody, OsvResponse.class);
            OsvResponse response = filterWithdrawn(raw);

            packageCache.put(cacheKey, new CacheEntry<>(response, cacheExpiration()));
            return toOptionalResponse(response);
          } catch (IOException e) {
            throw new OsvClientException("OSV query failed for " + packageName, e);
          }
        },
        executorService);
  }

  /**
   * Batch-checks packages and hydrates each reported vulnerability id into a full OSV record. The
   * returned list preserves the order of {@code packages}; entries without vulnerabilities are
   * {@code null}.
   */
  public CompletableFuture<Optional<OsvBatchResponse>> checkDependencies(
      List<OsvPackage> packages) {
    Objects.requireNonNull(packages, "Packages list cannot be null");

    return CompletableFuture.supplyAsync(() -> doCheckDependencies(packages), executorService);
  }

  private Optional<OsvBatchResponse> doCheckDependencies(List<OsvPackage> packages) {
    Instant exp = cacheExpiration();
    List<OsvResponse> finalResults = new ArrayList<>(Collections.nCopies(packages.size(), null));
    List<OsvQuery> queriesToFetch = new ArrayList<>();
    List<Integer> fetchIndices = new ArrayList<>();

    for (int i = 0; i < packages.size(); i++) {
      OsvPackage pkg = packages.get(i);
      CacheEntry<OsvResponse> entry = packageCache.get(cacheKey(pkg));
      if (entry != null && entry.isFresh()) {
        finalResults.set(i, emptyToNull(entry.value));
      } else {
        queriesToFetch.add(new OsvQuery(pkg.version(), pkg));
        fetchIndices.add(i);
      }
    }

    if (queriesToFetch.isEmpty()) {
      return Optional.of(new OsvBatchResponse(finalResults));
    }

    // 1. Batch lookup (minimal records: id + modified), chunked to the OSV batch limit.
    List<OsvResponse> minimalResults = fetchMinimalRecords(queriesToFetch);

    // 2. Hydrate every distinct vulnerability id into a full record.
    Map<String, OsvVulnerability> hydrated = hydrate(collectIds(minimalResults), exp);

    // 3. Rebuild per-package responses with the full records and refresh the cache.
    for (int j = 0; j < fetchIndices.size(); j++) {
      int originalIndex = fetchIndices.get(j);
      OsvResponse minimal = j < minimalResults.size() ? minimalResults.get(j) : null;

      if (minimal == null || minimal.vulns() == null || minimal.vulns().isEmpty()) {
        // Only cache a definitive "no vulnerabilities" when OSV actually answered this query.
        if (j < minimalResults.size()) {
          packageCache.put(
              cacheKey(packages.get(originalIndex)),
              new CacheEntry<>(new OsvResponse(List.of()), exp));
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
      packageCache.put(cacheKey(packages.get(originalIndex)), new CacheEntry<>(full, exp));
    }

    return Optional.of(new OsvBatchResponse(finalResults));
  }

  /** Runs the querybatch call in chunks, following per-result pagination tokens. */
  private List<OsvResponse> fetchMinimalRecords(List<OsvQuery> queries) {
    List<OsvResponse> results = new ArrayList<>(Collections.nCopies(queries.size(), null));

    for (int start = 0; start < queries.size(); start += MAX_BATCH_SIZE) {
      int end = Math.min(start + MAX_BATCH_SIZE, queries.size());
      List<OsvQuery> chunk = new ArrayList<>(queries.subList(start, end));
      List<Integer> chunkIndices = new ArrayList<>();
      for (int i = start; i < end; i++) {
        chunkIndices.add(i);
      }

      for (int page = 0; page < MAX_PAGES && !chunk.isEmpty(); page++) {
        OsvBatchResponse batch = postBatch(chunk);
        List<OsvResponse> batchResults = batch.results() == null ? List.of() : batch.results();

        List<OsvQuery> nextChunk = new ArrayList<>();
        List<Integer> nextIndices = new ArrayList<>();

        for (int k = 0; k < chunk.size(); k++) {
          OsvResponse pageResult = k < batchResults.size() ? batchResults.get(k) : null;
          int globalIndex = chunkIndices.get(k);
          results.set(globalIndex, mergeVulns(results.get(globalIndex), pageResult));

          if (pageResult != null
              && pageResult.nextPageToken() != null
              && !pageResult.nextPageToken().isBlank()) {
            nextChunk.add(chunk.get(k).withPageToken(pageResult.nextPageToken()));
            nextIndices.add(globalIndex);
          }
        }
        chunk = nextChunk;
        chunkIndices = nextIndices;
      }
      if (!chunk.isEmpty()) {
        LOG.warn(
            "OSV pagination cap reached ("
                + MAX_PAGES
                + " pages) for "
                + chunk.size()
                + " package(s); remaining vulnerabilities may not be reported. "
                + "Re-scan to fetch more.");
      }
    }
    return results;
  }

  private OsvBatchResponse postBatch(List<OsvQuery> queries) {
    try {
      String requestBody = objectMapper.writeValueAsString(new OsvBatchQuery(queries));
      String responseBody = postWithRetry(ProjectConstants.OSV_API_BATCH_URL, requestBody);
      if (responseBody == null || responseBody.isEmpty()) {
        throw new OsvClientException("Empty response from OSV batch API", null);
      }
      return objectMapper.readValue(responseBody, OsvBatchResponse.class);
    } catch (IOException e) {
      throw new OsvClientException("OSV batch query failed", e);
    }
  }

  /**
   * Fetches full records for the given ids, using the per-id cache. Individual failures degrade to
   * the minimal record instead of failing the whole scan.
   */
  private Map<String, OsvVulnerability> hydrate(Set<String> ids, Instant exp) {
    Map<String, OsvVulnerability> hydrated = new ConcurrentHashMap<>();
    List<CompletableFuture<Void>> tasks = new ArrayList<>();

    for (String id : ids) {
      CacheEntry<OsvVulnerability> cached = vulnCache.get(id);
      if (cached != null && cached.isFresh()) {
        hydrated.put(id, cached.value);
        continue;
      }
      tasks.add(
          CompletableFuture.runAsync(
              () -> {
                OsvVulnerability full = fetchVulnerability(id);
                if (full != null) {
                  hydrated.put(id, full);
                  vulnCache.put(id, new CacheEntry<>(full, exp));
                }
              },
              executorService));
    }

    CompletableFuture.allOf(tasks.toArray(new CompletableFuture<?>[0])).join();
    return hydrated;
  }

  private OsvVulnerability fetchVulnerability(String id) {
    String url = ProjectConstants.OSV_API_VULNS_URL + URLEncoder.encode(id, StandardCharsets.UTF_8);
    try {
      String body = getWithRetry(url);
      return objectMapper.readValue(body, OsvVulnerability.class);
    } catch (IOException e) {
      LOG.warn("Failed to hydrate OSV record " + id + "; falling back to minimal data", e);
      return null;
    }
  }

  /** GET with limited retries for transient failures. */
  private String getWithRetry(String url) throws IOException {
    IOException lastFailure = null;
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        return HttpRequests.request(url)
            .connectTimeout(HTTP_TIMEOUT_MS)
            .readTimeout(HTTP_TIMEOUT_MS)
            .readString();
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

  /** POST with limited retries for transient failures. */
  private String postWithRetry(String url, String requestBody) throws IOException {
    IOException lastFailure = null;
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        return HttpRequests.post(url, "application/json")
            .connectTimeout(HTTP_TIMEOUT_MS)
            .readTimeout(HTTP_TIMEOUT_MS)
            .connect(
                request -> {
                  request.write(requestBody);
                  return request.readString();
                });
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
