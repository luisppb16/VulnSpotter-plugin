/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.projectsapo.model.OsvBatchQuery;
import com.projectsapo.model.OsvBatchResponse;
import com.projectsapo.model.OsvPackage;
import com.projectsapo.model.OsvQuery;
import com.projectsapo.model.OsvResponse;
import com.projectsapo.util.ProjectConstants;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Client for interacting with the OSV.dev API to check for vulnerabilities.
 * Uses a cached thread pool for asynchronous execution to ensure compatibility with Java 11/17.
 */
public class OsvClient {

  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final ExecutorService executorService;

  public OsvClient() {
    // Changed from newVirtualThreadPerTaskExecutor to newCachedThreadPool for compatibility
    this(Executors.newCachedThreadPool());
  }

  public OsvClient(ExecutorService executorService) {
    this(
        executorService,
        HttpClient.newBuilder()
            .executor(executorService)
            .connectTimeout(Duration.ofSeconds(10))
            .build());
  }

  public OsvClient(ExecutorService executorService, HttpClient httpClient) {
    this.executorService = executorService;
    this.httpClient = httpClient;
    this.objectMapper = new ObjectMapper();
  }

  public CompletableFuture<Optional<OsvResponse>> checkDependency(
      String packageName, String version, String ecosystem) {
    Objects.requireNonNull(packageName, "Package name cannot be null");
    Objects.requireNonNull(version, "Version cannot be null");
    Objects.requireNonNull(ecosystem, "Ecosystem cannot be null");

    return CompletableFuture.supplyAsync(
            () -> {
              try {
                OsvPackage osvPackage = new OsvPackage(packageName, ecosystem, version);
                OsvQuery query = new OsvQuery(version, osvPackage);
                return objectMapper.writeValueAsString(query);
              } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
              }
            },
            executorService)
        .thenCompose(
            requestBody -> {
              HttpRequest request =
                  HttpRequest.newBuilder()
                      .uri(URI.create(ProjectConstants.OSV_API_URL))
                      .header("Content-Type", "application/json")
                      .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                      .build();

              return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());
            })
        .thenApply(
            response -> {
              if (response.statusCode() == 200) {
                if (response.body().equals("{}")) {
                  return Optional.<OsvResponse>empty();
                }

                try {
                  OsvResponse osvResponse =
                      objectMapper.readValue(response.body(), OsvResponse.class);
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
              try {
                List<OsvQuery> queries =
                    packages.stream().map(pkg -> new OsvQuery(pkg.version(), pkg)).toList();

                OsvBatchQuery batchQuery = new OsvBatchQuery(queries);
                return objectMapper.writeValueAsString(batchQuery);
              } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
              }
            },
            executorService)
        .thenCompose(
            requestBody -> {
              HttpRequest request =
                  HttpRequest.newBuilder()
                      .uri(URI.create(ProjectConstants.OSV_API_BATCH_URL))
                      .header("Content-Type", "application/json")
                      .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                      .build();

              return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());
            })
        .thenApply(
            response -> {
              if (response.statusCode() == 200) {
                try {
                  OsvBatchResponse batchResponse =
                      objectMapper.readValue(response.body(), OsvBatchResponse.class);
                  return Optional.of(batchResponse);
                } catch (IOException e) {
                  return Optional.<OsvBatchResponse>empty();
                }
              } else {
                return Optional.<OsvBatchResponse>empty();
              }
            })
        .exceptionally(ex -> Optional.empty());
  }
}
