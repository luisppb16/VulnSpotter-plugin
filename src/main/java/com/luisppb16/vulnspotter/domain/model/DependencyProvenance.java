/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * How a scanned dependency reached the project, derived from its dependency chains: a chain of a
 * single node means a declared (direct) dependency, a longer chain means a transitive one whose
 * first node is the declared root that pulled it in.
 */
public record DependencyProvenance(Kind kind, List<String> transitiveRoots) {

  public static final DependencyProvenance UNKNOWN_PROVENANCE =
      new DependencyProvenance(Kind.UNKNOWN, List.of());

  public static DependencyProvenance of(Set<List<String>> chains) {
    if (chains == null || chains.isEmpty()) {
      return UNKNOWN_PROVENANCE;
    }
    List<String> roots =
        chains.stream()
            .filter(chain -> chain.size() > 1)
            .map(chain -> chain.getFirst())
            .filter(Objects::nonNull)
            .distinct()
            .sorted()
            .limit(3)
            .collect(Collectors.toList());
    boolean direct = chains.stream().anyMatch(chain -> chain.size() == 1);
    boolean transitive = !roots.isEmpty();
    if (direct && transitive) {
      return new DependencyProvenance(Kind.MIXED, roots);
    }
    if (transitive) {
      return new DependencyProvenance(Kind.TRANSITIVE, roots);
    }
    return new DependencyProvenance(Kind.DECLARED, List.of());
  }

  public boolean known() {
    return kind == Kind.DECLARED || kind == Kind.TRANSITIVE || kind == Kind.MIXED;
  }

  public String label() {
    return switch (kind) {
      case DECLARED -> "Direct dependency";
      case TRANSITIVE -> labelFromRoots("Transitive dependency");
      case MIXED -> labelFromRoots("Direct and transitive dependency");
      case UNKNOWN -> "Provenance unavailable";
    };
  }

  public String shortLabel() {
    return switch (kind) {
      case DECLARED -> "Declared";
      case TRANSITIVE -> "Transitive";
      case MIXED -> "Direct + transitive";
      case UNKNOWN -> "Unknown";
    };
  }

  private String labelFromRoots(String base) {
    if (transitiveRoots.isEmpty()) {
      return base;
    }
    return base + " (via " + String.join(", ", transitiveRoots) + ")";
  }

  public enum Kind {
    DECLARED,
    TRANSITIVE,
    MIXED,
    UNKNOWN
  }
}
