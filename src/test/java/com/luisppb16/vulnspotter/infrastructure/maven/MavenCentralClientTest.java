/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.maven;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.intellij.util.io.HttpRequests;
import com.intellij.util.io.RequestBuilder;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import java.io.IOException;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("MavenCentralClient Test Suite")
class MavenCentralClientTest {

  private static final String METADATA_URL =
      "https://repo1.maven.org/maven2/org/acme/starter-web/maven-metadata.xml";

  private static final String METADATA =
      """
      <metadata>
        <groupId>org.acme</groupId>
        <artifactId>starter-web</artifactId>
        <versioning>
          <versions>
            <version>0.9.0</version>
            <version>1.0.0</version>
            <version>1.1.0</version>
            <version>2.0.0-SNAPSHOT</version>
          </versions>
        </versioning>
      </metadata>\
      """;

  private static final String ROOT_POM_WITH_BOM =
      """
      <project>
        <groupId>org.acme</groupId>
        <artifactId>starter-web</artifactId>
        <version>1.1.0</version>
        <properties><acme.version>2.0.0</acme.version></properties>
        <dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>org.acme</groupId>
              <artifactId>acme-bom</artifactId>
              <version>${acme.version}</version>
              <type>pom</type>
              <scope>import</scope>
            </dependency>
          </dependencies>
        </dependencyManagement>
      </project>\
      """;

  private static final String BOM_POM =
      """
      <project>
        <groupId>org.acme</groupId>
        <artifactId>acme-bom</artifactId>
        <version>2.0.0</version>
        <packaging>pom</packaging>
        <properties><child.version>2.1.0</child.version></properties>
        <dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>g.c</groupId>
              <artifactId>c</artifactId>
              <version>${child.version}</version>
            </dependency>
          </dependencies>
        </dependencyManagement>
      </project>\
      """;

  private static final String ROOT_POM_WITH_WALK =
      """
      <project>
        <groupId>org.acme</groupId>
        <artifactId>starter-web</artifactId>
        <version>1.1.0</version>
        <dependencies>
          <dependency>
            <groupId>org.acme</groupId>
            <artifactId>starter-json</artifactId>
            <version>0.5.0</version>
          </dependency>
        </dependencies>
      </project>\
      """;

  private static final String JSON_POM_WITH_CHILD =
      """
      <project>
        <groupId>org.acme</groupId>
        <artifactId>starter-json</artifactId>
        <version>0.5.0</version>
        <dependencies>
          <dependency>
            <groupId>g.c</groupId>
            <artifactId>c</artifactId>
            <version>2.1.0</version>
          </dependency>
        </dependencies>
      </project>\
      """;

  private static final String ROOT_POM_UNRESOLVABLE =
      """
      <project>
        <groupId>org.acme</groupId>
        <artifactId>starter-web</artifactId>
        <version>1.1.0</version>
        <dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>g.c</groupId>
              <artifactId>c</artifactId>
              <version>${missing.property}</version>
            </dependency>
          </dependencies>
        </dependencyManagement>
      </project>\
      """;

  private MavenCentralClient client;
  private MockedStatic<HttpRequests> httpRequests;
  private MockedStatic<VulnSpotterSettings> settingsMock;

  private static String pomUrl(String artifact, String version) {
    return "https://repo1.maven.org/maven2/org/acme/"
        + artifact
        + "/"
        + artifact
        + "-"
        + version
        + ".pom";
  }

  @BeforeEach
  void setUp() {
    // The tests stub every URL, so the on-disk POM cache is off (it points at the IDE sandbox
    // and would leak one test's stubbed responses into the next).
    client = new MavenCentralClient(null);

    VulnSpotterSettings settings = mock(VulnSpotterSettings.class);
    lenient().doReturn(false).when(settings).isDisableVulnerabilityCache();
    settingsMock = mockStatic(VulnSpotterSettings.class);
    settingsMock.when(VulnSpotterSettings::getInstance).thenReturn(settings);
  }

  @AfterEach
  void tearDown() {
    if (httpRequests != null) {
      httpRequests.close();
    }
    if (settingsMock != null) {
      settingsMock.close();
    }
  }

  private void stubUrl(String url, String content) throws IOException {
    RequestBuilder builder = mock(RequestBuilder.class);
    httpRequests.when(() -> HttpRequests.request(url)).thenReturn(builder);
    when(builder.connectTimeout(anyInt())).thenReturn(builder);
    when(builder.readTimeout(anyInt())).thenReturn(builder);
    when(builder.readString()).thenReturn(content);
  }

  private void stubFailingUrl() throws IOException {
    RequestBuilder builder = mock(RequestBuilder.class);
    httpRequests.when(() -> HttpRequests.request(METADATA_URL)).thenReturn(builder);
    when(builder.connectTimeout(anyInt())).thenReturn(builder);
    when(builder.readTimeout(anyInt())).thenReturn(builder);
    when(builder.readString()).thenThrow(new IOException("404"));
  }

  @Test
  @DisplayName("should_deduce_the_first_parent_release_whose_bom_ships_the_fixed_child")
  void deducesFirstParentReleaseWhoseBomShipsTheFixedChild() throws IOException {
    // Given: the parent chain resolves the child through an imported BOM.
    httpRequests = mockStatic(HttpRequests.class);
    stubUrl(METADATA_URL, METADATA);
    stubUrl(pomUrl("starter-web", "1.1.0"), ROOT_POM_WITH_BOM);
    stubUrl(pomUrl("acme-bom", "2.0.0"), BOM_POM);

    // When: the installed parent version is 1.0.0 and the required child fix is 2.0.0.
    Optional<MavenCentralClient.FixingVersion> fixing =
        client.fixingVersion("org.acme", "starter-web", "1.0.0", "g.c:c", "2.0.0");

    // Then: 0.9.0/1.0.0 are skipped, snapshots are skipped, and 1.1.0 is the first fixing release.
    assertThat(fixing).contains(new MavenCentralClient.FixingVersion("1.1.0", "2.1.0"));
  }

  @Test
  @DisplayName("should_walk_intermediate_poms_to_find_the_child_version")
  void walksIntermediatePomsToFindTheChildVersion() throws IOException {
    // Given: the child is declared with a literal version inside an intermediate POM.
    httpRequests = mockStatic(HttpRequests.class);
    stubUrl(METADATA_URL, METADATA);
    stubUrl(pomUrl("starter-web", "1.1.0"), ROOT_POM_WITH_WALK);
    stubUrl(pomUrl("starter-json", "0.5.0"), JSON_POM_WITH_CHILD);

    // When
    Optional<MavenCentralClient.FixingVersion> fixing =
        client.fixingVersion("org.acme", "starter-web", "1.0.0", "g.c:c", "2.0.0");

    // Then
    assertThat(fixing).contains(new MavenCentralClient.FixingVersion("1.1.0", "2.1.0"));
  }

  @Test
  @DisplayName("should_resolve_the_child_version_against_the_declaring_pom_properties")
  void resolvesTheChildVersionAgainstTheDeclaringPomProperties() throws IOException {
    // Given: the intermediate POM declares the child through a property of its own.
    String jsonPomWithProps =
        """
        <project>
          <groupId>org.acme</groupId>
          <artifactId>starter-json</artifactId>
          <version>0.5.0</version>
          <properties><child.version>2.1.0</child.version></properties>
          <dependencies>
            <dependency>
              <groupId>g.c</groupId>
              <artifactId>c</artifactId>
              <version>${child.version}</version>
            </dependency>
          </dependencies>
        </project>\
        """;
    httpRequests = mockStatic(HttpRequests.class);
    stubUrl(METADATA_URL, METADATA);
    stubUrl(pomUrl("starter-web", "1.1.0"), ROOT_POM_WITH_WALK);
    stubUrl(pomUrl("starter-json", "0.5.0"), jsonPomWithProps);

    // When
    Optional<MavenCentralClient.FixingVersion> fixing =
        client.fixingVersion("org.acme", "starter-web", "1.0.0", "g.c:c", "2.0.0");

    // Then
    assertThat(fixing).contains(new MavenCentralClient.FixingVersion("1.1.0", "2.1.0"));
  }

  @Test
  @DisplayName("should_yield_no_parent_upgrade_when_metadata_is_unavailable")
  void yieldsNoParentUpgradeWhenMetadataIsUnavailable() throws IOException {
    // Given: the version list of the parent cannot be fetched.
    httpRequests = mockStatic(HttpRequests.class);
    stubFailingUrl();

    // When
    Optional<MavenCentralClient.FixingVersion> fixing =
        client.fixingVersion("org.acme", "starter-web", "1.0.0", "g.c:c", "2.0.0");

    // Then: the search degrades to "no suggestion" instead of failing.
    assertThat(fixing).isEmpty();
  }

  @Test
  @DisplayName("should_yield_no_parent_upgrade_when_the_child_version_stays_unresolvable")
  void yieldsNoParentUpgradeWhenTheChildVersionStaysUnresolvable() throws IOException {
    // Given: the management entry's property does not resolve in any reachable POM.
    httpRequests = mockStatic(HttpRequests.class);
    stubUrl(METADATA_URL, METADATA);
    stubUrl(pomUrl("starter-web", "1.1.0"), ROOT_POM_UNRESOLVABLE);

    // When
    Optional<MavenCentralClient.FixingVersion> fixing =
        client.fixingVersion("org.acme", "starter-web", "1.0.0", "g.c:c", "2.0.0");

    // Then
    assertThat(fixing).isEmpty();
  }

  @Test
  @DisplayName("should_not_deduce_a_fix_when_the_candidate_parent_ships_an_older_child")
  void doesNotDeduceAFixWhenTheCandidateParentShipsAnOlderChild() throws IOException {
    // Given: the only new release still manages an older child than the fix.
    String bomWithOldChild =
        """
        <project>
          <groupId>org.acme</groupId>
          <artifactId>acme-bom</artifactId>
          <version>2.0.0</version>
          <properties><child.version>1.9.0</child.version></properties>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>g.c</groupId>
                <artifactId>c</artifactId>
                <version>${child.version}</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
        </project>\
        """;
    httpRequests = mockStatic(HttpRequests.class);
    stubUrl(METADATA_URL, METADATA);
    stubUrl(pomUrl("starter-web", "1.1.0"), ROOT_POM_WITH_BOM);
    stubUrl(pomUrl("acme-bom", "2.0.0"), bomWithOldChild);

    // When
    Optional<MavenCentralClient.FixingVersion> fixing =
        client.fixingVersion("org.acme", "starter-web", "1.0.0", "g.c:c", "2.0.0");

    // Then: 1.9.0 counts as un-fixed, so no parent release qualifies.
    assertThat(fixing).isEmpty();
  }
}
