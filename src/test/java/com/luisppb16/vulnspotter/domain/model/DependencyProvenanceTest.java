/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
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
}
