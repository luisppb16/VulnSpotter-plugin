/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.projectsapo.model.OsvBatchResponse;
import com.projectsapo.model.OsvPackage;
import com.projectsapo.model.OsvResponse;
import com.projectsapo.util.ProjectConstants;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("OsvClient Test Suite")
class OsvClientTest {

  @Mock private HttpClient httpClient;
  @Mock private HttpResponse<String> httpResponse;

  private OsvClient client;
  private final ExecutorService executor = Executors.newSingleThreadExecutor();
  private final ObjectMapper objectMapper = new ObjectMapper();

  @BeforeEach
  void setUp() {
    client = new OsvClient(executor, httpClient);
  }

  @Nested
  @DisplayName("checkDependency (Single)")
  class CheckDependency {

    @Test
    @DisplayName("should_return_response_when_api_returns_200_and_data")
    void shouldReturnResponseWhenSuccess() throws Exception {
      // Given
      String json = "{\"vulns\": []}";
      when(httpResponse.statusCode()).thenReturn(200);
      when(httpResponse.body()).thenReturn(json);
      when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
          .thenReturn(CompletableFuture.completedFuture(httpResponse));

      // When
      Optional<OsvResponse> result = client.checkDependency("pkg", "1.0", "Maven").join();

      // Then
      assertThat(result).isPresent();

      ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
      verify(httpClient).sendAsync(captor.capture(), any());
      HttpRequest request = captor.getValue();
      assertThat(request.uri()).isEqualTo(URI.create(ProjectConstants.OSV_API_URL));
      assertThat(request.method()).isEqualTo("POST");
    }

    @Test
    @DisplayName("should_return_empty_when_api_returns_empty_json")
    void shouldReturnEmptyWhenEmptyJson() throws Exception {
      // Given
      when(httpResponse.statusCode()).thenReturn(200);
      when(httpResponse.body()).thenReturn("{}");
      when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
          .thenReturn(CompletableFuture.completedFuture(httpResponse));

      // When
      Optional<OsvResponse> result = client.checkDependency("pkg", "1.0", "Maven").join();

      // Then
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("should_return_empty_when_api_returns_error_code")
    void shouldReturnEmptyWhenError() throws Exception {
      // Given
      when(httpResponse.statusCode()).thenReturn(404);
      when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
          .thenReturn(CompletableFuture.completedFuture(httpResponse));

      // When
      Optional<OsvResponse> result = client.checkDependency("pkg", "1.0", "Maven").join();

      // Then
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("should_return_empty_on_exception")
    void shouldReturnEmptyOnException() throws Exception {
      // Given
      when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
          .thenReturn(CompletableFuture.failedFuture(new IOException("Network error")));

      // When
      Optional<OsvResponse> result = client.checkDependency("pkg", "1.0", "Maven").join();

      // Then
      assertThat(result).isEmpty();
    }
  }

  @Nested
  @DisplayName("checkDependencies (Batch)")
  class CheckDependencies {

    @Test
    @DisplayName("should_send_correct_batch_request_and_parse_response")
    void shouldSendBatchRequest() throws Exception {
      // Given
      OsvPackage pkg1 = new OsvPackage("pkg1", "Maven", "1.0.0");
      List<OsvPackage> packages = List.of(pkg1);

      String jsonResponse = "{\"results\": [{\"vulns\": []}]}";
      when(httpResponse.statusCode()).thenReturn(200);
      when(httpResponse.body()).thenReturn(jsonResponse);
      when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
          .thenReturn(CompletableFuture.completedFuture(httpResponse));

      // When
      Optional<OsvBatchResponse> result = client.checkDependencies(packages).join();

      // Then
      assertThat(result).isPresent();
      assertThat(result.get().results()).hasSize(1);

      ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
      verify(httpClient).sendAsync(captor.capture(), any());
      HttpRequest request = captor.getValue();
      assertThat(request.uri()).isEqualTo(URI.create(ProjectConstants.OSV_API_BATCH_URL));
    }

    @Test
    @DisplayName("should_return_empty_on_api_error")
    void shouldReturnEmptyOnError() throws Exception {
       // Given
      when(httpResponse.statusCode()).thenReturn(500);
      when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
          .thenReturn(CompletableFuture.completedFuture(httpResponse));

      // When
      Optional<OsvBatchResponse> result = client.checkDependencies(List.of(new OsvPackage("a", "b", "c"))).join();

      // Then
      assertThat(result).isEmpty();
    }
  }
}
