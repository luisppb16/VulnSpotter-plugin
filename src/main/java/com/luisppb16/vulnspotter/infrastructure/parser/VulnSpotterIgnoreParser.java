/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.parser;

import com.luisppb16.vulnspotter.domain.model.Ecosystem;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Parses the project's {@code .vulnspotterignore} file.
 *
 * <p>Each non-comment line is a pattern matched against the package name (e.g. {@code com.foo:bar})
 * or against {@code ecosystem:name} (e.g. {@code Maven:com.foo:bar}). A {@code *} wildcard matches
 * any sequence, so {@code com.foo:*} ignores every artifact of that group. A specific installed
 * version can be ignored with {@code name@version} or {@code ecosystem:name@version} (e.g. {@code
 * Maven:com.foo:bar@1.2.3}).
 *
 * <p>Matching is case-sensitive for ecosystems whose names are case-sensitive (Maven {@code
 * group:artifact}, Go module paths) and case-insensitive for npm/PyPI, where package names are
 * case-insensitive. Lowercasing Maven/Go names would break matching and silently fail to ignore.
 */
public final class VulnSpotterIgnoreParser {

  /**
   * Compiled globs, memoized per pattern text: {@code isIgnored} runs once per scanned package, so
   * recompiling each {@code *} pattern per package turns one scan into thousands of {@code
   * Pattern.compile} calls. The ignore-file pattern set is small and pure text, so the cache does
   * not grow unbounded.
   */
  private static final Map<String, Pattern> GLOB_CACHE = new ConcurrentHashMap<>();

  private VulnSpotterIgnoreParser() {}

  /** True when the package matches any ignore pattern (by name or ecosystem:name, with globs). */
  public static boolean isIgnored(Set<String> patterns, OsvPackage pkg) {
    if (patterns.isEmpty()) {
      return false;
    }
    String ecosystem = pkg.ecosystem();
    boolean caseSensitive = Ecosystem.isCaseSensitive(ecosystem);
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

  private static Pattern globToRegex(String glob) {
    return GLOB_CACHE.computeIfAbsent(glob, VulnSpotterIgnoreParser::compileGlob);
  }

  private static Pattern compileGlob(String glob) {
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
