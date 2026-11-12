/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.jetbrains.annotations.Nullable;

/**
 * How a scanned dependency reached the project, derived from its dependency chains: a chain of a
 * single node means a declared (direct) dependency, a longer chain means a transitive one whose
 * first node is the declared root that pulled it in.
 */
public record DependencyProvenance(Kind kind, List<String> transitiveRoots) {

  public static final DependencyProvenance UNKNOWN_PROVENANCE =
      new DependencyProvenance(Kind.UNKNOWN, List.of());

  /**
   * Pseudo-root for classpath edges no build-script declaration explains: those the IDE toolchain
   * (the {@code intellijPlatform} block) injects as provided.
   */
  public static final String PLATFORM_ROOT = "intellijPlatform (provided)";

  /** True only for the synthetic platform root; a real {@code group:artifact} never matches. */
  public static boolean isPlatformRoot(@Nullable String node) {
    return PLATFORM_ROOT.equals(node);
  }

  public static DependencyProvenance of(Set<List<String>> chains) {
    if (chains == null || chains.isEmpty()) {
      return UNKNOWN_PROVENANCE;
    }
    List<String> roots =
        chains.stream()
            .filter(chain -> chain.size() > 1)
            .filter(chain -> !isPlatformRoot(chain.getFirst()))
            .map(List::getFirst)
            .filter(Objects::nonNull)
            .distinct()
            .sorted()
            .limit(3)
            .collect(Collectors.toList());
    boolean direct = chains.stream().anyMatch(chain -> chain.size() == 1);
    boolean platform =
        chains.stream().anyMatch(chain -> chain.size() > 1 && isPlatformRoot(chain.getFirst()));
    if (!roots.isEmpty()) {
      return direct
          ? new DependencyProvenance(Kind.MIXED, roots)
          : new DependencyProvenance(Kind.TRANSITIVE, roots);
    }
    if (direct) {
      return new DependencyProvenance(Kind.DECLARED, List.of());
    }
    if (platform) {
      return new DependencyProvenance(Kind.PROVIDED, List.of());
    }
    return new DependencyProvenance(Kind.DECLARED, List.of());
  }

  private static String appendKnownVersion(Map<String, String> rootVersions, String root) {
    String version = rootVersions.get(root);
    return version == null ? "" : " " + version;
  }

  public boolean known() {
    return kind != Kind.UNKNOWN;
  }

  public String label() {
    return switch (kind) {
      case DECLARED -> "Direct dependency";
      case TRANSITIVE -> labelFromRoots(Map.of(), "Transitive dependency");
      case MIXED -> labelFromRoots(Map.of(), "Direct and transitive dependency");
      case PROVIDED -> "Provided by the intellijPlatform toolchain";
      case UNKNOWN -> "Provenance unavailable";
    };
  }

  /**
   * {@link #label()} with each transitive root annotated by its currently resolved version
   * (scan-wide name → version index), e.g. {@code "Transitive dependency (via root:x 1.2.3)"}.
   * Roots the index does not know keep the bare-name form.
   */
  public String label(Map<String, String> rootVersions) {
    Map<String, String> versions = rootVersions == null ? Map.of() : rootVersions;
    return switch (kind) {
      case DECLARED -> "Direct dependency";
      case TRANSITIVE -> labelFromRoots(versions, "Transitive dependency");
      case MIXED -> labelFromRoots(versions, "Direct and transitive dependency");
      case PROVIDED -> "Provided by the intellijPlatform toolchain";
      case UNKNOWN -> "Provenance unavailable";
    };
  }

  public String shortLabel() {
    return switch (kind) {
      case DECLARED -> "Declared";
      case TRANSITIVE -> "Transitive";
      case MIXED -> "Direct + transitive";
      case PROVIDED -> "Provided";
      case UNKNOWN -> "Unknown";
    };
  }

  private String labelFromRoots(Map<String, String> rootVersions, String base) {
    if (transitiveRoots.isEmpty()) {
      return base;
    }
    String via =
        transitiveRoots.stream()
            .map(root -> root + appendKnownVersion(rootVersions, root))
            .collect(Collectors.joining(", "));
    return base + " (via " + via + ")";
  }

  public enum Kind {
    DECLARED,
    TRANSITIVE,
    MIXED,
    PROVIDED,
    UNKNOWN
  }
}
