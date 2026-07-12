/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.parser;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Parses the project's {@code .vulnspotterignore} file.
 *
 * <p>Each non-comment line is a pattern matched against the package name (e.g. {@code
 * com.foo:bar}) or against {@code ecosystem:name} (e.g. {@code Maven:com.foo:bar}). A {@code *}
 * wildcard matches any sequence, so {@code com.foo:*} ignores every artifact of that group. A
 * specific installed version can be ignored with {@code name@version} or {@code
 * ecosystem:name@version} (e.g. {@code Maven:com.foo:bar@1.2.3}).
 *
 * <p>Matching is case-sensitive for ecosystems whose names are case-sensitive (Maven {@code
 * group:artifact}, Go module paths) and case-insensitive for npm/PyPI, where package names are
 * case-insensitive. Lowercasing Maven/Go names would break matching and silently fail to ignore.
 */
public final class VulnSpotterIgnoreParser {

  private static final Logger LOG = Logger.getInstance(VulnSpotterIgnoreParser.class);

  private VulnSpotterIgnoreParser() {}

  public static Set<String> getIgnoredDependencies(Project project) {
    if (project.getBasePath() == null) {
      return Collections.emptySet();
    }

    Path ignoreFilePath = Paths.get(project.getBasePath(), ".vulnspotterignore");
    if (!Files.exists(ignoreFilePath)) {
      return Collections.emptySet();
    }

    try {
      List<String> lines = Files.readAllLines(ignoreFilePath);
      Set<String> ignored = new HashSet<>();
      for (String line : lines) {
        String trimmed = line.trim();
        if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
          ignored.add(trimmed);
        }
      }
      return ignored;
    } catch (IOException e) {
      LOG.warn("Failed to read .vulnspotterignore; ignore rules are not being applied", e);
      return Collections.emptySet();
    }
  }

  /** True when the package matches any ignore pattern (by name or ecosystem:name, with globs). */
  public static boolean isIgnored(Set<String> patterns, OsvPackage pkg) {
    if (patterns.isEmpty()) {
      return false;
    }
    boolean caseSensitive = isCaseSensitiveEcosystem(pkg.ecosystem());
    String name = caseSensitive ? pkg.name() : pkg.name().toLowerCase(Locale.ROOT);
    String qualified =
        caseSensitive
            ? pkg.ecosystem() + ":" + pkg.name()
            : (pkg.ecosystem() + ":" + pkg.name()).toLowerCase(Locale.ROOT);
    String version = pkg.version();

    for (String pattern : patterns) {
      String normalized = caseSensitive ? pattern : pattern.toLowerCase(Locale.ROOT);
      if (matches(normalized, name, qualified, version)) {
        return true;
      }
    }
    return false;
  }

  private static boolean matches(String pattern, String name, String qualified, String version) {
    // Split an optional "@version" suffix: "name@1.2.3" / "ecosystem:name@1.2.3".
    String patternName = pattern;
    String patternVersion = null;
    int at = pattern.lastIndexOf('@');
    if (at >= 0) {
      patternName = pattern.substring(0, at);
      patternVersion = pattern.substring(at + 1);
    }

    boolean nameMatched;
    if (patternName.indexOf('*') >= 0) {
      Pattern glob = globToRegex(patternName);
      nameMatched = glob.matcher(name).matches() || glob.matcher(qualified).matches();
    } else {
      nameMatched = patternName.equals(name) || patternName.equals(qualified);
    }
    if (!nameMatched) {
      return false;
    }
    // No version constraint → any installed version of the package is ignored.
    if (patternVersion == null || patternVersion.isEmpty()) {
      return true;
    }
    return version != null && version.equals(patternVersion);
  }

  private static boolean isCaseSensitiveEcosystem(String ecosystem) {
    if (ecosystem == null) return true;
    return !"npm".equalsIgnoreCase(ecosystem) && !"PyPI".equalsIgnoreCase(ecosystem);
  }

  private static Pattern globToRegex(String glob) {
    String[] parts = glob.split("\\*", -1);
    StringBuilder regex = new StringBuilder();
    for (int i = 0; i < parts.length; i++) {
      if (i > 0) {
        regex.append(".*");
      }
      if (!parts[i].isEmpty()) {
        regex.append(Pattern.quote(parts[i]));
      }
    }
    return Pattern.compile(regex.toString());
  }
}