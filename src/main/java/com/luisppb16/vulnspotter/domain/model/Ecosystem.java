/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

/**
 * Single source for everything that depends on an OSV ecosystem id: the canonical names (kept as
 * strings because {@code OsvPackage} serializes them verbatim and OSV feeds can carry ids we do not
 * model), the per-ecosystem name-matching case rule, the manifest file, and the upgrade snippet
 * format. Adding or re-spelling an ecosystem touches only this class.
 */
public final class Ecosystem {

  public static final String MAVEN = "Maven";
  public static final String NPM = "npm";
  public static final String PYPI = "PyPI";
  public static final String GO = "Go";

  private Ecosystem() {
    throw new UnsupportedOperationException("Utility class");
  }

  /**
   * npm/PyPI package names are case-insensitive; Maven ({@code group:artifact}) and Go module paths
   * are not, and an unknown or null ecosystem conservatively stays case-sensitive (lowercasing a
   * case-sensitive name can silently fail to match).
   */
  public static boolean isCaseSensitive(String osvId) {
    if (osvId == null) {
      return true;
    }
    return !"npm".equalsIgnoreCase(osvId) && !"PyPI".equalsIgnoreCase(osvId);
  }

  /** Manifest file for the ecosystem; {@code "dependencies"} when null or unmapped. */
  public static String manifestFile(String osvId) {
    return switch (osvId == null ? "" : osvId) {
      case MAVEN -> "pom.xml";
      case NPM -> "package.json";
      case PYPI -> "requirements.txt";
      case GO -> "go.mod";
      default -> "dependencies";
    };
  }

  /**
   * Manifest snippet pinning {@code fix} for a package, in the ecosystem's own syntax. Unknown or
   * null ecosystems fall back to the bare {@code name:fix} coordinate.
   */
  public static String upgradeSnippet(String osvId, String name, String fix) {
    if (osvId == null) {
      return name + ":" + fix;
    }
    return switch (osvId) {
      case MAVEN -> {
        int colon = name.indexOf(':');
        String group = colon >= 0 ? name.substring(0, colon) : name;
        String artifact = colon >= 0 ? name.substring(colon + 1) : name;
        yield "<dependency>\n"
            + "  <groupId>"
            + group
            + "</groupId>\n"
            + "  <artifactId>"
            + artifact
            + "</artifactId>\n"
            + "  <version>"
            + fix
            + "</version>\n"
            + "</dependency>";
      }
      case NPM -> "npm install " + name + "@" + fix;
      case PYPI -> name + "==" + fix;
      case GO -> name + " v" + fix;
      default -> name + ":" + fix;
    };
  }
}
