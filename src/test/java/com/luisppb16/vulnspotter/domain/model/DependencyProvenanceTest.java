/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@DisplayName("DependencyProvenance Test Suite")
class DependencyProvenanceTest {

  private static List<Set<List<String>>> wideChainSets() {
    return List.of(
        Set.of(List.of("a1", "t"), List.of("a2", "t"), List.of("a3", "t"), List.of("a4", "t")));
  }

  @Test
  @DisplayName("should_report_unknown_provenance_when_no_chains_exist")
  void unknownWhenNoChainsExist() {
    assertThat(DependencyProvenance.of(null).kind()).isEqualTo(DependencyProvenance.Kind.UNKNOWN);
    assertThat(DependencyProvenance.of(Set.of()).kind())
        .isEqualTo(DependencyProvenance.Kind.UNKNOWN);
    assertThat(DependencyProvenance.of(null).label()).isEqualTo("Provenance unavailable");
    assertThat(DependencyProvenance.of(null).shortLabel()).isEqualTo("Unknown");
    assertThat(DependencyProvenance.of(null).known()).isFalse();
  }

  @Test
  @DisplayName("should_report_declared_for_singleton_chains")
  void declaredFromSingletonChains() {
    DependencyProvenance provenance = DependencyProvenance.of(Set.of(List.of("g:a")));

    assertThat(provenance.kind()).isEqualTo(DependencyProvenance.Kind.DECLARED);
    assertThat(provenance.transitiveRoots()).isEmpty();
    assertThat(provenance.label()).isEqualTo("Direct dependency");
    assertThat(provenance.shortLabel()).isEqualTo("Declared");
  }

  @Test
  @DisplayName("should_report_transitive_with_sorted_distinct_roots")
  void transitiveFromChainedRoots() {
    DependencyProvenance provenance =
        DependencyProvenance.of(Set.of(List.of("b:a", "g:b"), List.of("a:z", "g:b")));

    assertThat(provenance.kind()).isEqualTo(DependencyProvenance.Kind.TRANSITIVE);
    assertThat(provenance.transitiveRoots()).containsExactly("a:z", "b:a");
    assertThat(provenance.label()).isEqualTo("Transitive dependency (via a:z, b:a)");
    assertThat(provenance.shortLabel()).isEqualTo("Transitive");
  }

  @Test
  @DisplayName("should_report_mixed_when_the_same_artifact_is_both_direct_and_transitive")
  void mixedFromDirectAndTransitiveChains() {
    DependencyProvenance provenance =
        DependencyProvenance.of(Set.of(List.of("g:a"), List.of("root:x", "g:a")));

    assertThat(provenance.kind()).isEqualTo(DependencyProvenance.Kind.MIXED);
    assertThat(provenance.label()).isEqualTo("Direct and transitive dependency (via root:x)");
    assertThat(provenance.shortLabel()).isEqualTo("Direct + transitive");
  }

  @ParameterizedTest(name = "chain count {0} keeps at most three roots")
  @MethodSource("wideChainSets")
  @DisplayName("should_cap_the_transitive_roots_list_at_three")
  void capsTransitiveRootsAtThree(Set<List<String>> chains) {
    assertThat(DependencyProvenance.of(chains).transitiveRoots()).hasSize(3);
  }

  @Test
  @DisplayName("should_annotate_transitive_roots_with_index_versions")
  void annotatesTransitiveRootsWithIndexVersions() {
    // Given: one root resolved by the scan index and one that the index does not know.
    DependencyProvenance provenance =
        DependencyProvenance.of(Set.of(List.of("b:a", "g:b"), List.of("a:z", "g:b")));

    // Then: known roots carry their version, unknown ones stay bare, null index is tolerated.
    assertThat(provenance.label(Map.of("b:a", "1.2.3")))
        .isEqualTo("Transitive dependency (via a:z, b:a 1.2.3)");
    assertThat(provenance.label(Map.of())).isEqualTo("Transitive dependency (via a:z, b:a)");
    assertThat(provenance.label(null)).isEqualTo("Transitive dependency (via a:z, b:a)");
  }

  @Test
  @DisplayName("should_annotate_mixed_label_with_index_versions")
  void annotatesMixedLabelWithIndexVersions() {
    // Given
    DependencyProvenance provenance =
        DependencyProvenance.of(Set.of(List.of("g:a"), List.of("root:x", "g:a")));

    // Then
    assertThat(provenance.label(Map.of("root:x", "4.1.0")))
        .isEqualTo("Direct and transitive dependency (via root:x 4.1.0)");
  }

  @Test
  @DisplayName("should_keep_declared_label_unaffected_by_the_index")
  void keepsDeclaredLabelUnaffectedByTheIndex() {
    // Given
    DependencyProvenance provenance = DependencyProvenance.of(Set.of(List.of("b:a")));

    // Then: a declared dependency never lists roots, with or without the version index.
    assertThat(provenance.label(Map.of("b:a", "1.2.3"))).isEqualTo("Direct dependency");
  }

  @Test
  @DisplayName("should_yield_the_provided_kind_for_platform_only_chains")
  void shouldYieldTheProvidedKindForPlatformOnlyChains() {
    // Given: a chain the IDE toolchain injected with its pseudo-root.
    DependencyProvenance provenance =
        DependencyProvenance.of(Set.of(List.of(DependencyProvenance.PLATFORM_ROOT, "g:c")));

    // Then
    assertThat(provenance.kind()).isEqualTo(DependencyProvenance.Kind.PROVIDED);
    assertThat(provenance.transitiveRoots()).isEmpty();
    assertThat(provenance.known()).isTrue();
    assertThat(provenance.label()).isEqualTo("Provided by the intellijPlatform toolchain");
    assertThat(provenance.label(Map.of())).isEqualTo("Provided by the intellijPlatform toolchain");
    assertThat(provenance.shortLabel()).isEqualTo("Provided");
  }

  @Test
  @DisplayName("should_drop_the_platform_root_from_the_roots_of_mixed_provenance")
  void shouldDropThePlatformRootFromTheRootsOfMixedProvenance() {
    // Given: a platform chain next to a real parent chain.
    DependencyProvenance provenance =
        DependencyProvenance.of(
            Set.of(List.of(DependencyProvenance.PLATFORM_ROOT, "g:c"), List.of("root:p", "g:c")));

    // Then: only the real root drives the remediation paths.
    assertThat(provenance.kind()).isEqualTo(DependencyProvenance.Kind.TRANSITIVE);
    assertThat(provenance.transitiveRoots()).containsExactly("root:p");
  }

  @Test
  @DisplayName("should_keep_declared_when_a_single_node_chain_exists_next_to_platform")
  void shouldKeepDeclaredWhenASingleNodeChainExistsNextToPlatform() {
    // Given
    DependencyProvenance provenance =
        DependencyProvenance.of(
            Set.of(List.of("g:a"), List.of(DependencyProvenance.PLATFORM_ROOT, "g:a")));

    // Then: the actionable truth is "the build script declares it".
    assertThat(provenance.kind()).isEqualTo(DependencyProvenance.Kind.DECLARED);
    assertThat(provenance.transitiveRoots()).isEmpty();
  }

  @Test
  @DisplayName("isPlatformRoot_matches_only_the_synthetic_root")
  void isPlatformRootMatchesOnlyTheSyntheticRoot() {
    assertThat(DependencyProvenance.isPlatformRoot(DependencyProvenance.PLATFORM_ROOT)).isTrue();
    assertThat(DependencyProvenance.isPlatformRoot("com.example:lib")).isFalse();
  }
}
