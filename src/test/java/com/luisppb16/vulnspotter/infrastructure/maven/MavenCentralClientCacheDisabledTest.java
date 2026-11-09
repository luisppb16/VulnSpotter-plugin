/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.maven;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import com.intellij.util.io.HttpRequests;
import com.intellij.util.io.RequestBuilder;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("MavenCentralClient Cache Disabled Test Suite")
class MavenCentralClientCacheDisabledTest {

  private static final String METADATA_URL =
      "https://repo1.maven.org/maven2/org/acme/starter-web/maven-metadata.xml";
  private static final String WEB_POM_URL =
      "https://repo1.maven.org/maven2/org/acme/starter-web/starter-web-1.2.0.pom";

  private static final String METADATA =
      """
      <metadata>
        <groupId>org.acme</groupId>
        <artifactId>starter-web</artifactId>
        <versioning>
          <versions>
            <version>1.1.0</version>
            <version>1.2.0</version>
          </versions>
        </versioning>
      </metadata>\
      """;

  private static final String WEB_POM =
      """
      <project>
        <groupId>org.acme</groupId>
        <artifactId>starter-web</artifactId>
        <version>1.2.0</version>
        <dependencies>
          <dependency>
            <groupId>g.c</groupId>
            <artifactId>c</artifactId>
            <version>2.1.0</version>
          </dependency>
        </dependencies>
      </project>\
      """;

  private MavenCentralClient client;
  private VulnSpotterSettings settings;
  private MockedStatic<HttpRequests> httpRequests;
  private MockedStatic<VulnSpotterSettings> settingsMock;

  private static void stubUrl(MockedStatic<HttpRequests> http, String url, String content)
      throws IOException {
    RequestBuilder builder = mock(RequestBuilder.class);
    http.when(() -> HttpRequests.request(url)).thenReturn(builder);
    when(builder.connectTimeout(anyInt())).thenReturn(builder);
    when(builder.readTimeout(anyInt())).thenReturn(builder);
    when(builder.readString()).thenReturn(content);
  }

  @BeforeEach
  void setUp() {
    client = new MavenCentralClient(null);
    settings = mock(VulnSpotterSettings.class);
    settingsMock = mockStatic(VulnSpotterSettings.class);
    settingsMock.when(VulnSpotterSettings::getInstance).thenReturn(settings);
  }

  @AfterEach
  void tearDown() {
    if (settingsMock != null) {
      settingsMock.close();
    }
    if (httpRequests != null) {
      httpRequests.close();
    }
  }

  private void cacheDisabled() {
    when(settings.isDisableVulnerabilityCache()).thenReturn(true);
  }

  private void cacheEnabled() {
    when(settings.isDisableVulnerabilityCache()).thenReturn(false);
  }

  @Test
  @DisplayName("should_refetch_remediation_metadata_while_caching_is_disabled")
  void shouldRefetchRemediationMetadataWhileCachingIsDisabled() throws IOException {
    // Given: caching disabled; the same parent resolves twice.
    httpRequests = mockStatic(HttpRequests.class);
    stubUrl(httpRequests, METADATA_URL, METADATA);
    stubUrl(httpRequests, WEB_POM_URL, WEB_POM);
    cacheDisabled();

    // When
    client.fixingVersion("org.acme", "starter-web", "1.1.0", "g.c:c", "2.0.0");
    client.fixingVersion("org.acme", "starter-web", "1.1.0", "g.c:c", "2.0.0");

    // Then: both resolutions went to Maven Central; nothing was served from the session cache.
    httpRequests.verify(() -> HttpRequests.request(METADATA_URL), times(2));
    httpRequests.verify(() -> HttpRequests.request(WEB_POM_URL), times(2));
  }

  @Test
  @DisplayName("should_serve_session_caches_while_caching_is_enabled")
  void shouldServeSessionCachesWhileCachingIsEnabled() throws IOException {
    // Given: caching stays on (default) and the same parent resolves twice.
    httpRequests = mockStatic(HttpRequests.class);
    stubUrl(httpRequests, METADATA_URL, METADATA);
    stubUrl(httpRequests, WEB_POM_URL, WEB_POM);

    // When
    client.fixingVersion("org.acme", "starter-web", "1.1.0", "g.c:c", "2.0.0");
    client.fixingVersion("org.acme", "starter-web", "1.1.0", "g.c:c", "2.0.0");

    // Then: only the first resolution hit Maven Central; the second was served from the cache.
    httpRequests.verify(() -> HttpRequests.request(METADATA_URL), times(1));
    httpRequests.verify(() -> HttpRequests.request(WEB_POM_URL), times(1));
  }

  @Test
  @DisplayName("should_not_store_answers_while_caching_is_disabled")
  void shouldNotStoreAnswersWhileCachingIsDisabled() throws IOException {
    // Given: one resolution runs with caching disabled and the second with it re-enabled.
    httpRequests = mockStatic(HttpRequests.class);
    stubUrl(httpRequests, METADATA_URL, METADATA);
    stubUrl(httpRequests, WEB_POM_URL, WEB_POM);
    cacheDisabled();

    // When
    client.fixingVersion("org.acme", "starter-web", "1.1.0", "g.c:c", "2.0.0");
    cacheEnabled();
    client.fixingVersion("org.acme", "starter-web", "1.1.0", "g.c:c", "2.0.0");

    // Then: the disabled pass stored nothing, so the re-enabled one still goes to the network.
    httpRequests.verify(() -> HttpRequests.request(METADATA_URL), times(2));
    httpRequests.verify(() -> HttpRequests.request(WEB_POM_URL), times(2));
  }
}
