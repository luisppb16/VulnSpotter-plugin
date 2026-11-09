/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * The dependency chains of one scanned package merged into a single path tree, in the shape of a
 * {@code mvn dependency:tree} listing: shared prefixes collapse into one branch, each chain's last
 * node keeps the {@code target} mark and children stay in natural {@code group:artifact} order. The
 * root is virtual — its children are the chains' first nodes (the direct dependencies), the
 * renderer supplies the project root line.
 */
public record DependencyChainTree(Node root) {

  public static DependencyChainTree of(Set<List<String>> chains) {
    Objects.requireNonNull(chains, "Chains cannot be null");
    NodeBuilder builder = new NodeBuilder("");
    for (List<String> chain : chains) {
      if (chain == null
          || chain.isEmpty()
          || chain.stream().anyMatch(step -> step == null || step.isBlank())) {
        continue;
      }
      NodeBuilder node = builder;
      for (String step : chain) {
        node = node.child(step);
      }
      node.target = true;
    }
    return new DependencyChainTree(builder.freeze());
  }

  public record Node(String name, boolean target, List<Node> children) {}

  private static final class NodeBuilder {

    private final String name;
    private final Map<String, NodeBuilder> children = new TreeMap<>();
    private boolean target;

    private NodeBuilder(String name) {
      this.name = name;
    }

    private NodeBuilder child(String step) {
      return children.computeIfAbsent(step, NodeBuilder::new);
    }

    private Node freeze() {
      List<Node> frozen = new ArrayList<>(children.size());
      for (NodeBuilder child : children.values()) {
        frozen.add(child.freeze());
      }
      return new Node(name, target, List.copyOf(frozen));
    }
  }
}
