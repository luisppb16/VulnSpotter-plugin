/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.projectsapo.model.OsvBatchResponse;
import com.projectsapo.model.OsvPackage;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class OsvClientChunkingTest {

  private HttpClient httpClient;
  private HttpResponse<String> httpResponse;
  private OsvClient client;
  private ExecutorService executor;

  @BeforeEach
  void setUp() {
    httpClient = mock(HttpClient.class);
    httpResponse = mock(HttpResponse.class);
    executor = Executors.newCachedThreadPool();
    client = new OsvClient(executor, httpClient);
  }

  @AfterEach
  void tearDown() {
    executor.shutdown();
  }

  @Test
  @DisplayName("should_split_1200_packages_into_3_chunks_of_500")
  void shouldSplitIntoChunks() throws Exception {
    // Given
    int totalPackages = 1200;
    List<OsvPackage> packages = new ArrayList<>();
    for (int i = 0; i < totalPackages; i++) {
      packages.add(new OsvPackage("pkg-" + i, "Maven", "1.0"));
    }

    when(httpResponse.statusCode()).thenReturn(200);
    // Return a valid JSON with at least one result so allResults is not empty
    when(httpResponse.body()).thenReturn("{\"results\": [{\"vulns\": []}]}");
    when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
        .thenReturn(httpResponse);

    // When
    Optional<OsvBatchResponse> result = client.checkDependencies(packages).join();

    // Then
    assertThat(result).isPresent();
    // 500 + 500 + 200 = 1200
    verify(httpClient, times(3)).send(any(), any());
  }

  @Test
  @DisplayName("should_handle_empty_package_list")
  void shouldHandleEmptyList() {
    // When
    Optional<OsvBatchResponse> result = client.checkDependencies(List.of()).join();

    // Then
    assertThat(result).isPresent();
    assertThat(result.get().results()).isEmpty();
  }
}
