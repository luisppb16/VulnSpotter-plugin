/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.osv;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import com.intellij.util.io.HttpRequests;
import com.intellij.util.io.RequestBuilder;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import com.luisppb16.vulnspotter.testsupport.DirectExecutorService;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("OsvClient Cache Disabled Test Suite")
class OsvClientCacheDisabledTest {

  private static final String MODIFIED = "2025-01-01T00:00:00Z";

  private static final String BATCH_JSON =
      "{\"results\":[{\"vulns\":[{\"id\":\"GHSA-1\",\"modified\":\"" + MODIFIED + "\"}]}]}";
  private static final String FULL_JSON =
      "{\"id\":\"GHSA-1\",\"modified\":\"" + MODIFIED + "\",\"summary\":\"s\"}";

  private ExecutorService executorService;
  private OsvClient client;
  private VulnSpotterSettings settings;
  private MockedStatic<HttpRequests> httpRequests;
  private MockedStatic<VulnSpotterSettings> settingsMock;

  /** Minimal helpers mirroring the real HttpRequests builder chain. */
  private void stubPost() throws IOException {
    RequestBuilder postBuilder = mock(RequestBuilder.class);
    httpRequests.when(() -> HttpRequests.post(anyString(), anyString())).thenReturn(postBuilder);
    when(postBuilder.connectTimeout(anyInt())).thenReturn(postBuilder);
    when(postBuilder.readTimeout(anyInt())).thenReturn(postBuilder);
    when(postBuilder.connect(any())).thenReturn(BATCH_JSON);
  }

  private void stubGet() throws IOException {
    RequestBuilder getBuilder = mock(RequestBuilder.class);
    httpRequests.when(() -> HttpRequests.request(anyString())).thenReturn(getBuilder);
    when(getBuilder.connectTimeout(anyInt())).thenReturn(getBuilder);
    when(getBuilder.readTimeout(anyInt())).thenReturn(getBuilder);
    when(getBuilder.readString()).thenReturn(FULL_JSON);
  }

  @BeforeEach
  void setUp() {
    // Inline executor: the OsvClient pipeline (batch POST -> hydration GET) runs on the test
    // thread, which is where the Mockito static stubbing was configured and verified.
    executorService = new DirectExecutorService();
    client = new OsvClient(executorService);

    settings = mock(VulnSpotterSettings.class);
    lenient().when(settings.getCacheDurationMinutes()).thenReturn(60);
    settingsMock = mockStatic(VulnSpotterSettings.class);
    settingsMock.when(VulnSpotterSettings::getInstance).thenReturn(settings);
  }

  @AfterEach
  void tearDown() {
    executorService.shutdownNow();
    if (settingsMock != null) {
      settingsMock.close();
    }
    if (httpRequests != null) {
      httpRequests.close();
    }
  }

  @Test
  @DisplayName("should_refetch_every_scan_while_cache_is_disabled")
  void shouldRefetchEveryScanWhileCacheIsDisabled() throws IOException {
    // Given: vulnerability caching disabled by the user; two scans run over the same package.
    httpRequests = mockStatic(HttpRequests.class);
    stubPost();
    stubGet();
    when(settings.isDisableVulnerabilityCache()).thenReturn(true);

    // When
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();

    // Then: both scans hit OSV.dev — nothing was served from the cache.
    httpRequests.verify(() -> HttpRequests.post(anyString(), anyString()), times(2));
  }

  @Test
  @DisplayName("should_not_store_answers_while_cache_is_disabled")
  void shouldNotStoreAnswersWhileCacheIsDisabled() throws IOException {
    // Given: one scan runs with caching disabled.
    httpRequests = mockStatic(HttpRequests.class);
    stubPost();
    stubGet();
    when(settings.isDisableVulnerabilityCache()).thenReturn(true, false);

    // When: the user re-enables caching and the same package re-scans.
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();

    // Then: the disabled scan stored nothing, so the re-enabled scan must go to the network.
    httpRequests.verify(() -> HttpRequests.post(anyString(), anyString()), times(2));
  }

  @Test
  @DisplayName("should_serve_cached_answers_when_cache_is_enabled")
  void shouldServeCachedAnswersWhenCacheIsEnabled() throws IOException {
    // Given: caching stays enabled (default) and the same package scans twice.
    httpRequests = mockStatic(HttpRequests.class);
    stubPost();
    stubGet();
    when(settings.isDisableVulnerabilityCache()).thenReturn(false);

    // When
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();

    // Then: only the first scan went to OSV.dev; the second was answered from the cache.
    httpRequests.verify(() -> HttpRequests.post(anyString(), anyString()), times(1));
    httpRequests.verify(() -> HttpRequests.request(anyString()), times(1));
  }

  @Test
  @DisplayName("should_revalidate_hydration_by_stamp_while_cache_is_disabled")
  void shouldRevalidateHydrationByStampWhileCacheIsDisabled() throws IOException {
    // Given: caching disabled, two scans carrying an unchanged "modified" stamp in the batch.
    httpRequests = mockStatic(HttpRequests.class);
    stubPost();
    stubGet();
    when(settings.isDisableVulnerabilityCache()).thenReturn(true);

    // When
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();

    // Then: every scan re-POSTs (no package cache), but hydration stayed stamp-validated (1 GET).
    httpRequests.verify(() -> HttpRequests.post(anyString(), anyString()), times(2));
    httpRequests.verify(() -> HttpRequests.request(anyString()), times(1));
  }
}
