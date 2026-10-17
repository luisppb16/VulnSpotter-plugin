/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@DisplayName("Ecosystem Test Suite")
class EcosystemTest {

  static Stream<Arguments> manifestFiles() {
    return Stream.of(
        arguments("Maven", "pom.xml"),
        arguments("npm", "package.json"),
        arguments("PyPI", "requirements.txt"),
        arguments("Go", "go.mod"),
        arguments("Cargo", "dependencies"),
        arguments(null, "dependencies"),
        arguments("", "dependencies"));
  }

  static Stream<Arguments> caseSensitivity() {
    return Stream.of(
        arguments("Maven", true),
        arguments("Go", true),
        arguments(null, true),
        arguments("Cargo", true),
        arguments("npm", false),
        arguments("NPM", false),
        arguments("PyPI", false),
        arguments("pypi", false));
  }

  @Test
  @DisplayName("should_map_wire_ids_exactly_as_osv_publishes_them")
  void shouldMapWireIdsExactly() {
    // Given / When / Then: the canonical ids must keep OSV's exact casing.
    assertThat(Ecosystem.MAVEN).isEqualTo("Maven");
    assertThat(Ecosystem.NPM).isEqualTo("npm");
    assertThat(Ecosystem.PYPI).isEqualTo("PyPI");
    assertThat(Ecosystem.GO).isEqualTo("Go");
  }

  @ParameterizedTest(name = "manifest of {0} is {1}")
  @MethodSource("manifestFiles")
  @DisplayName("should_map_each_ecosystem_to_its_manifest_file")
  void shouldMapManifestFiles(String osvId, String expected) {
    assertThat(Ecosystem.manifestFile(osvId)).isEqualTo(expected);
  }

  @ParameterizedTest(name = "\"{0}\" case-sensitive: {1}")
  @MethodSource("caseSensitivity")
  @DisplayName("should_apply_the_matching_case_rule_per_ecosystem")
  void shouldApplyCaseRule(String osvId, boolean expectedSensitive) {
    assertThat(Ecosystem.isCaseSensitive(osvId)).isEqualTo(expectedSensitive);
  }

  @Test
  @DisplayName("should_split_maven_coordinates_in_the_upgrade_snippet")
  void shouldBuildMavenSnippet() {
    // When / Then
    assertThat(Ecosystem.upgradeSnippet("Maven", "com.example:lib", "1.2.3"))
        .isEqualTo(
            "<dependency>\n"
                + "  <groupId>com.example</groupId>\n"
                + "  <artifactId>lib</artifactId>\n"
                + "  <version>1.2.3</version>\n"
                + "</dependency>");
    // A name without a group also renders a valid pom snippet.
    assertThat(Ecosystem.upgradeSnippet("Maven", "lib", "1.2.3"))
        .contains("<artifactId>lib</artifactId>");
  }

  @Test
  @DisplayName("should_build_snippets_for_npm_pypi_and_go")
  void shouldBuildOtherSnippets() {
    assertThat(Ecosystem.upgradeSnippet("npm", "react", "18.3.1"))
        .isEqualTo("npm install react@18.3.1");
    assertThat(Ecosystem.upgradeSnippet("PyPI", "flask", "3.0.0")).isEqualTo("flask==3.0.0");
    assertThat(Ecosystem.upgradeSnippet("Go", "example.com/m", "1.4.0"))
        .isEqualTo("example.com/m v1.4.0");
  }

  @Test
  @DisplayName("should_fall_back_to_bare_coordinate_for_unknown_or_null_ecosystem")
  void shouldFallBackForUnknown() {
    assertThat(Ecosystem.upgradeSnippet("Cargo", "serde", "1.0.0")).isEqualTo("serde:1.0.0");
    assertThat(Ecosystem.upgradeSnippet(null, "serde", "1.0.0")).isEqualTo("serde:1.0.0");
  }
}
