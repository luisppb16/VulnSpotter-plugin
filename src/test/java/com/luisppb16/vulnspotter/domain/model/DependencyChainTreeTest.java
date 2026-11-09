/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DependencyChainTree Test Suite")
class DependencyChainTreeTest {

  @Test
  @DisplayName("should_build_single_edge_tree_for_declared_chain")
  void shouldBuildSingleEdgeTreeForDeclaredChain() {
    DependencyChainTree tree = DependencyChainTree.of(Set.of(List.of("a:b")));

    assertThat(tree.root().children()).hasSize(1);
    DependencyChainTree.Node node = tree.root().children().getFirst();
    assertThat(node.name()).isEqualTo("a:b");
    assertThat(node.target()).isTrue();
    assertThat(node.children()).isEmpty();
  }

  @Test
  @DisplayName("should_merge_shared_prefixes_and_mark_only_path_endpoints_as_target")
  void shouldMergeSharedPrefixesAndMarkOnlyEndpointsAsTarget() {
    DependencyChainTree tree =
        DependencyChainTree.of(Set.of(List.of("a", "b", "t"), List.of("a", "b", "c", "t")));

    DependencyChainTree.Node a = tree.root().children().getFirst();
    assertThat(a.name()).isEqualTo("a");
    assertThat(a.target()).isFalse();
    DependencyChainTree.Node b = a.children().getFirst();
    assertThat(b.name()).isEqualTo("b");
    assertThat(b.target()).isFalse();
    assertThat(b.children()).extracting(DependencyChainTree.Node::name).containsExactly("c", "t");
    DependencyChainTree.Node c = b.children().getFirst();
    assertThat(c.name()).isEqualTo("c");
    assertThat(c.target()).isFalse();
    assertThat(c.children().getFirst().name()).isEqualTo("t");
    assertThat(c.children().getFirst().target()).isTrue();
    DependencyChainTree.Node t = b.children().getLast();
    assertThat(t.name()).isEqualTo("t");
    assertThat(t.target()).isTrue();
  }

  @Test
  @DisplayName("should_mark_target_even_when_the_node_also_has_children")
  void shouldMarkTargetEvenWhenNodeAlsoHasChildren() {
    DependencyChainTree tree = DependencyChainTree.of(Set.of(List.of("t"), List.of("x", "y", "t")));

    DependencyChainTree.Node t = tree.root().children().getFirst();
    assertThat(t.name()).isEqualTo("t");
    assertThat(t.target()).isTrue();
    assertThat(t.children()).isEmpty();
    DependencyChainTree.Node x = tree.root().children().getLast();
    assertThat(x.name()).isEqualTo("x");
    assertThat(x.target()).isFalse();
    DependencyChainTree.Node y = x.children().getFirst();
    assertThat(y.target()).isFalse();
    assertThat(y.children().getFirst().target()).isTrue();
  }

  @Test
  @DisplayName("should_order_children_naturally_across_roots")
  void shouldOrderChildrenNaturallyAcrossRoots() {
    DependencyChainTree tree =
        DependencyChainTree.of(Set.of(List.of("b", "x", "t"), List.of("a", "y", "t")));

    assertThat(tree.root().children())
        .extracting(DependencyChainTree.Node::name)
        .containsExactly("a", "b");
  }

  @Test
  @DisplayName("should_return_empty_root_for_empty_chains")
  void shouldReturnEmptyRootForEmptyChains() {
    DependencyChainTree tree = DependencyChainTree.of(Set.of());

    assertThat(tree.root().target()).isFalse();
    assertThat(tree.root().children()).isEmpty();
  }

  @Test
  @DisplayName("should_fail_fast_on_null_chains")
  void shouldFailFastOnNullChains() {
    assertThatThrownBy(() -> DependencyChainTree.of(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  @DisplayName("should_skip_malformed_chains")
  void shouldSkipMalformedChains() {
    DependencyChainTree tree =
        DependencyChainTree.of(
            Set.of(
                List.of(" "), List.of("a", "b"), List.of("a", " "), Arrays.asList("a", null, "b")));

    DependencyChainTree.Node a = tree.root().children().getFirst();
    DependencyChainTree.Node b = a.children().getFirst();
    assertThat(b.name()).isEqualTo("b");
    assertThat(b.target()).isTrue();
    assertThat(b.children()).isEmpty();
  }
}
