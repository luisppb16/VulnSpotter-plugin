/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.VulnSpotter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intellij.util.io.HttpRequests;
import com.VulnSpotter.model.OsvBatchQuery;
import com.VulnSpotter.model.OsvBatchResponse;
import com.VulnSpotter.model.OsvPackage;
import com.VulnSpotter.model.OsvQuery;
import com.VulnSpotter.model.OsvResponse;
import com.VulnSpotter.settings.VulnSpotterSettings;
import com.VulnSpotter.util.ProjectConstants;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Client for interacting with the OSV.dev API to check for vulnerabilities. Uses IntelliJ's
 * HttpRequests for network calls to integrate properly with IDE's proxy and avoid macOS keychain
 * popups.
 */
public class OsvClient {

  private final ObjectMapper objectMapper;
  private final ExecutorService executorService;
  private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

  public OsvClient() {
    this(Executors.newCachedThreadPool());
  }

  public OsvClient(ExecutorService executorService) {
    this.executorService = executorService;
    this.objectMapper = new ObjectMapper();
  }

  public CompletableFuture<Optional<OsvResponse>> checkDependency(
      String packageName, String version, String ecosystem) {
    Objects.requireNonNull(packageName, "Package name cannot be null");
    Objects.requireNonNull(version, "Version cannot be null");
    Objects.requireNonNull(ecosystem, "Ecosystem cannot be null");

    String cacheKey = ecosystem + ":" + packageName + ":" + version;
    CacheEntry entry = cache.get(cacheKey);
    if (entry != null && Instant.now().isBefore(entry.expiration)) {
      return CompletableFuture.completedFuture(Optional.ofNullable(entry.response));
    }

    return CompletableFuture.supplyAsync(
            () -> {
              try {
                OsvPackage osvPackage = new OsvPackage(packageName, ecosystem, version);
                OsvQuery query = new OsvQuery(version, osvPackage);
                String requestBody = objectMapper.writeValueAsString(query);

                return HttpRequests.post(ProjectConstants.OSV_API_URL, "application/json")
                    .connectTimeout(10000)
                    .readTimeout(10000)
                    .connect(
                        request -> {
                          request.write(requestBody);
                          return request.readString();
                        });
              } catch (IOException e) {
                throw new RuntimeException("Failed to call OSV API", e);
              }
            },
            executorService)
        .thenApply(
            responseBody -> {
              int cacheMinutes =
                  VulnSpotterSettings.getInstance() != null
                      ? VulnSpotterSettings.getInstance().getCacheDurationMinutes()
                      : 60;
              Instant exp = Instant.now().plus(Duration.ofMinutes(cacheMinutes));

              if (responseBody != null && !responseBody.isEmpty()) {
                if (responseBody.equals("{}")) {
                  cache.put(cacheKey, new CacheEntry(null, exp));
                  return Optional.<OsvResponse>empty();
                }

                try {
                  OsvResponse osvResponse = objectMapper.readValue(responseBody, OsvResponse.class);
                  cache.put(cacheKey, new CacheEntry(osvResponse, exp));
                  return Optional.of(osvResponse);
                } catch (IOException e) {
                  return Optional.<OsvResponse>empty();
                }
              } else {
                return Optional.<OsvResponse>empty();
              }
            })
        .exceptionally(ex -> Optional.empty());
  }

  public CompletableFuture<Optional<OsvBatchResponse>> checkDependencies(
      List<OsvPackage> packages) {
    Objects.requireNonNull(packages, "Packages list cannot be null");

    return CompletableFuture.supplyAsync(
            () -> {
              int cacheMinutes =
                  VulnSpotterSettings.getInstance() != null
                      ? VulnSpotterSettings.getInstance().getCacheDurationMinutes()
                      : 60;
              Instant exp = Instant.now().plus(Duration.ofMinutes(cacheMinutes));

              List<OsvResponse> finalResults =
                  new ArrayList<>(Collections.nCopies(packages.size(), null));
              List<OsvQuery> queriesToFetch = new ArrayList<>();
              List<Integer> fetchIndices = new ArrayList<>();

              for (int i = 0; i < packages.size(); i++) {
                OsvPackage pkg = packages.get(i);
                String cacheKey = pkg.ecosystem() + ":" + pkg.name() + ":" + pkg.version();
                CacheEntry entry = cache.get(cacheKey);

                if (entry != null && Instant.now().isBefore(entry.expiration)) {
                  finalResults.set(i, entry.response);
                } else {
                  queriesToFetch.add(new OsvQuery(pkg.version(), pkg));
                  fetchIndices.add(i);
                }
              }

              if (queriesToFetch.isEmpty()) {
                return Optional.of(new OsvBatchResponse(finalResults));
              }

              try {
                OsvBatchQuery batchQuery = new OsvBatchQuery(queriesToFetch);
                String requestBody = objectMapper.writeValueAsString(batchQuery);

                String responseBody =
                    HttpRequests.post(ProjectConstants.OSV_API_BATCH_URL, "application/json")
                        .connectTimeout(10000)
                        .readTimeout(10000)
                        .connect(
                            request -> {
                              request.write(requestBody);
                              return request.readString();
                            });

                if (responseBody != null && !responseBody.isEmpty()) {
                  OsvBatchResponse partialResponse =
                      objectMapper.readValue(responseBody, OsvBatchResponse.class);
                  List<OsvResponse> fetchedResults =
                      partialResponse.results() == null
                          ? Collections.emptyList()
                          : partialResponse.results();

                  for (int j = 0; j < fetchIndices.size(); j++) {
                    int originalIndex = fetchIndices.get(j);
                    OsvResponse resp = j < fetchedResults.size() ? fetchedResults.get(j) : null;

                    // Empty objects in OSV denote no vulnerabilities, Jackson might parse as empty
                    // OsvResponse or null
                    finalResults.set(originalIndex, resp);

                    OsvPackage pkg = packages.get(originalIndex);
                    String cacheKey = pkg.ecosystem() + ":" + pkg.name() + ":" + pkg.version();
                    cache.put(cacheKey, new CacheEntry(resp, exp));
                  }
                }

                return Optional.of(new OsvBatchResponse(finalResults));
              } catch (IOException e) {
                throw new RuntimeException("Failed to call OSV Batch API", e);
              }
            },
            executorService)
        .exceptionally(ex -> Optional.empty());
  }

  private static class CacheEntry {
    OsvResponse response;
    Instant expiration;

    CacheEntry(OsvResponse r, Instant e) {
      this.response = r;
      this.expiration = e;
    }
  }
}
