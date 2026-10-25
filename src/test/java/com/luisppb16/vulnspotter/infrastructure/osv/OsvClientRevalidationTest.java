/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.osv;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import com.luisppb16.vulnspotter.domain.model.OsvBatchResponse;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
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
@DisplayName("OsvClient Revalidation Test Suite")
class OsvClientRevalidationTest {

  private static final String MODIFIED = "2025-01-01T00:00:00Z";
  private static final String OTHER_MODIFIED = "2025-06-01T00:00:00Z";

  private static final String BATCH_JSON =
      "{\"results\":[{\"vulns\":[{\"id\":\"GHSA-1\",\"modified\":\"" + MODIFIED + "\"}]}]}";
  private static final String FULL_JSON =
      "{\"id\":\"GHSA-1\",\"modified\":\"" + MODIFIED + "\",\"summary\":\"s\"}";
  private static final String BATCH_JSON_CHANGED =
      "{\"results\":[{\"vulns\":[{\"id\":\"GHSA-1\",\"modified\":\"" + OTHER_MODIFIED + "\"}]}]}";

  private ExecutorService executorService;
  private OsvClient client;
  private MockedStatic<HttpRequests> httpRequests;
  private MockedStatic<VulnSpotterSettings> settingsMock;

  /** Minimal helpers mirroring the real HttpRequests builder chain. */
  private static void stubPost(MockedStatic<HttpRequests> http, String batchJson)
      throws IOException {
    RequestBuilder postBuilder = mock(RequestBuilder.class);
    http.when(() -> HttpRequests.post(anyString(), anyString())).thenReturn(postBuilder);
    when(postBuilder.connectTimeout(anyInt())).thenReturn(postBuilder);
    when(postBuilder.readTimeout(anyInt())).thenReturn(postBuilder);
    when(postBuilder.connect(any())).thenReturn(batchJson);
  }

  private static void stubGet(MockedStatic<HttpRequests> http, String fullJson) throws IOException {
    RequestBuilder getBuilder = mock(RequestBuilder.class);
    http.when(() -> HttpRequests.request(anyString())).thenReturn(getBuilder);
    when(getBuilder.connectTimeout(anyInt())).thenReturn(getBuilder);
    when(getBuilder.readTimeout(anyInt())).thenReturn(getBuilder);
    when(getBuilder.readString()).thenReturn(fullJson);
  }

  /** Full record with the given {@code modified} component (seventh in the canonical order). */
  private static OsvVulnerability fullRecord(String modified) {
    return new OsvVulnerability(
        "GHSA-1", "s", null, null, null, null, modified, null, null, null, null);
  }

  @BeforeEach
  void setUp() {
    // Inline executor: the OsvClient pipeline (batch POST -> hydration GET) runs on the test
    // thread, which is where the Mockito static stubbing was configured and verified.
    executorService = new DirectExecutorService();
    client = new OsvClient(executorService);

    VulnSpotterSettings settings = mock(VulnSpotterSettings.class);
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
  @DisplayName("should_trust_cached_record_only_when_modified_stamps_match")
  void shouldTrustCachedOnlyWhenStampsMatch() {
    // Given
    OsvVulnerability cached = fullRecord(MODIFIED);

    // Then: exact same stamp → provably current even past the TTL.
    assertTrue(OsvClient.canTrustCached(cached, MODIFIED));
    // A different (or absent) stamp means OSV may have changed the record → must re-GET.
    assertFalse(OsvClient.canTrustCached(cached, OTHER_MODIFIED));
    assertFalse(OsvClient.canTrustCached(cached, null));
    assertFalse(OsvClient.canTrustCached(null, MODIFIED));
    assertFalse(OsvClient.canTrustCached(fullRecord(null), MODIFIED));
  }

  @Test
  @DisplayName("should_skip_hydration_gets_when_batch_modified_stamp_is_unchanged")
  void shouldSkipGetsWhenModifiedUnchanged() throws IOException {
    // Given: the batch POST returns minimal records carrying the same "modified" the full GET
    // returned before.
    httpRequests = mockStatic(HttpRequests.class);
    stubPost(httpRequests, BATCH_JSON);
    stubGet(httpRequests, FULL_JSON);

    // When: one full scan (batch POST + one hydration GET), then a sync invalidated only the batch
    // answers and re-scans: the hydration must notice the unchanged stamp and skip the GET.
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();
    client.invalidateCache();
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();

    // Then: exactly one GET /v1/vulns/{id} happened — the second hydration reused the record.
    httpRequests.verify(() -> HttpRequests.request(anyString()), times(1));
  }

  @Test
  @DisplayName("should_rehydrate_with_a_get_when_the_modified_stamp_changed")
  void shouldRehydrateWhenModifiedChanged() throws IOException {
    // Given
    httpRequests = mockStatic(HttpRequests.class);
    stubGet(httpRequests, FULL_JSON);

    // When: first scan sees stamp X; the sync invalidation + a changed batch answer (stamp Y)
    // must trigger a fresh hydration GET.
    stubPost(httpRequests, BATCH_JSON);
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();
    client.invalidateCache();
    stubPost(httpRequests, BATCH_JSON_CHANGED);
    client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();

    // Then
    httpRequests.verify(() -> HttpRequests.request(anyString()), times(2));
  }

  @Test
  @DisplayName("should_hydrate_by_get_an_id_whose_batch_record_lacks_a_modified_stamp")
  void shouldHydrateByGetAnIdWhoseBatchRecordLacksAModifiedStamp() throws IOException {
    // Given: the batch answer reports the advisory as a bare id-only record. Without "modified"
    // nothing proves a cached copy current, so the id must be hydrated by GET every scan instead
    // of silently degrading to the bare row (severity, ranges and references would be lost).
    httpRequests = mockStatic(HttpRequests.class);
    stubPost(httpRequests, "{\"results\":[{\"vulns\":[{\"id\":\"GHSA-2\"}]}]}");
    stubGet(
        httpRequests, "{\"id\":\"GHSA-2\",\"modified\":\"" + MODIFIED + "\",\"summary\":\"s\"}");

    // When: two scans over the same package, separated by the sync invalidation.
    OsvBatchResponse first =
        client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();
    client.invalidateCache();
    OsvBatchResponse second =
        client.checkDependencies(List.of(new OsvPackage("g:a", "Maven", "1.0"))).join();

    // Then: both scans hydrated the id (exactly two GETs), and neither row is the bare record.
    httpRequests.verify(() -> HttpRequests.request(anyString()), times(2));
    assertEquals("s", first.results().get(0).vulns().get(0).summary());
    assertEquals("s", second.results().get(0).vulns().get(0).summary());
  }
}
