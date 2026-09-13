/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Version comparison following Maven's {@code ComparableVersion} semantics: pre-release qualifiers
 * (alpha, beta, milestone, rc, snapshot) sort <b>below</b> the release, and {@code .RELEASE},
 * {@code .Final}, {@code ga} are equivalent to the plain release version.
 */
public final class VersionUtil {

  private VersionUtil() {}

  /**
   * Finds the best fixed version from a list of fixed versions, given the current version. The best
   * fixed version is the smallest version that is strictly greater than the current version,
   * ideally in the same major branch. Stable (non-pre-release) versions are always preferred over
   * pre-release ones (alpha/beta/milestone/rc/snapshot) so the user is never told to upgrade to an
   * alpha when a stable fix exists.
   *
   * @param fixedVersions List of fixed versions for the package.
   * @param currentVersion The current version of the package.
   * @return The best fixed version, or null if none is strictly greater.
   */
  public static String findBestFixedVersion(List<String> fixedVersions, String currentVersion) {
    if (fixedVersions == null || fixedVersions.isEmpty()) return null;
    if (currentVersion == null || currentVersion.isBlank()) {
      // Prefer a stable version, then the first available.
      String stable =
          fixedVersions.stream()
              .filter(v -> v != null && !v.isBlank() && !isPrerelease(v))
              .findFirst()
              .orElse(null);
      if (stable != null) return stable;
      return fixedVersions.stream().filter(v -> v != null && !v.isBlank()).findFirst().orElse(null);
    }

    String bestStable = bestAmong(fixedVersions, currentVersion, false);
    if (bestStable != null) {
      return bestStable;
    }
    return bestAmong(fixedVersions, currentVersion, true);
  }

  /**
   * Best candidate strictly greater than {@code currentVersion}, optionally restricted to
   * pre-release (when {@code prereleaseOnly} is true) or stable (when false) versions.
   */
  private static String bestAmong(
      List<String> fixedVersions, String currentVersion, boolean prereleaseOnly) {
    String bestVersion = null;
    boolean bestIsSameMajor = false;

    for (String fixed : fixedVersions) {
      if (fixed == null || fixed.isBlank()) continue;
      if (isPrerelease(fixed) != prereleaseOnly) continue;

      if (compareVersions(fixed, currentVersion) > 0) {
        boolean isSameMajor = isSameMajor(fixed, currentVersion);

        if (bestVersion == null) {
          bestVersion = fixed;
          bestIsSameMajor = isSameMajor;
        } else {
          if (isSameMajor && !bestIsSameMajor) {
            bestVersion = fixed;
            bestIsSameMajor = true;
          } else if (isSameMajor == bestIsSameMajor) {
            if (compareVersions(fixed, bestVersion) < 0) {
              bestVersion = fixed;
            }
          }
        }
      }
    }
    return bestVersion;
  }

  /** True for pre-release versions (alpha/beta/milestone/rc/preview/pre/snapshot qualifiers). */
  public static boolean isPrerelease(String version) {
    if (version == null || version.isBlank()) return false;
    for (VersionItem item : parse(version)) {
      if (item instanceof QualifierItem(String value) && qualifierRank(value) < qualifierRank("")) {
        return true;
      }
    }
    return false;
  }

  private static boolean isSameMajor(String v1, String v2) {
    return getMajor(v1).equals(getMajor(v2));
  }

  private static String getMajor(String version) {
    String clean = version.replaceAll("[^0-9.]", "");
    int idx = clean.indexOf('.');
    return idx == -1 ? clean : clean.substring(0, idx);
  }

  /**
   * Compares two version strings with Maven semantics.
   *
   * @return a negative integer, zero, or a positive integer as v1 is less than, equal to, or
   *     greater than v2.
   */
  public static int compareVersions(String v1, String v2) {
    List<VersionItem> items1 = parse(v1);
    List<VersionItem> items2 = parse(v2);

    int length = Math.max(items1.size(), items2.size());
    for (int i = 0; i < length; i++) {
      VersionItem a = i < items1.size() ? items1.get(i) : null;
      VersionItem b = i < items2.size() ? items2.get(i) : null;
      int comp = compareItems(a, b);
      if (comp != 0) {
        return comp;
      }
    }
    return 0;
  }

  /** Tokenize a version into numeric ({@link BigInteger}) and qualifier ({@link String}) items. */
  private static List<VersionItem> parse(String version) {
    String v = version == null ? "" : version.trim().toLowerCase(Locale.ROOT);
    List<VersionItem> items = new ArrayList<>();
    StringBuilder token = new StringBuilder();
    boolean digits = false;

    for (int i = 0; i < v.length(); i++) {
      char c = v.charAt(i);
      if (Character.isDigit(c)) {
        if (!token.isEmpty() && !digits) {
          items.add(new QualifierItem(normalizeQualifier(token.toString())));
          token.setLength(0);
        }
        digits = true;
        token.append(c);
      } else if (Character.isLetter(c)) {
        if (!token.isEmpty() && digits) {
          items.add(new NumberItem(new BigInteger(token.toString())));
          token.setLength(0);
        }
        digits = false;
        token.append(c);
      } else {
        // Separator ('.', '-', '_', '+', etc.)
        if (!token.isEmpty()) {
          items.add(
              digits
                  ? new NumberItem(new BigInteger(token.toString()))
                  : new QualifierItem(normalizeQualifier(token.toString())));
          token.setLength(0);
        }
        digits = false;
      }
    }
    if (!token.isEmpty()) {
      items.add(
          digits
              ? new NumberItem(new BigInteger(token.toString()))
              : new QualifierItem(normalizeQualifier(token.toString())));
    }

    // Trim trailing items equivalent to the plain release (".0", ".RELEASE", ".Final", "ga")
    while (!items.isEmpty()) {
      VersionItem last = items.getLast();
      boolean nullValue =
          (last instanceof NumberItem(BigInteger value) && value.signum() == 0)
              || (last instanceof QualifierItem(String qualifier) && qualifier.isEmpty());
      if (!nullValue) break;
      items.remove(items.size() - 1);
    }
    return items;
  }

  private static String normalizeQualifier(String qualifier) {
    return switch (qualifier) {
      case "ga", "final", "release" -> "";
      case "cr" -> "rc";
      case "a" -> "alpha";
      case "b" -> "beta";
      case "m" -> "milestone";
      default -> qualifier;
    };
  }

  /** Rank of a qualifier relative to the release (empty string). Higher = newer. */
  private static int qualifierRank(String qualifier) {
    return switch (qualifier) {
      case "alpha" -> 1;
      case "beta" -> 2;
      case "milestone" -> 3;
      case "rc", "preview", "pre" -> 4;
      case "snapshot" -> 5;
      case "" -> 6;
      case "sp" -> 7;
      default -> 8; // Unknown qualifiers sort after all known ones, lexically among themselves
    };
  }

  private static int compareItems(VersionItem a, VersionItem b) {
    if (a == null && b == null) return 0;
    if (a == null) return -compareItems(b, null);

    return switch (a) {
      case NumberItem numA ->
          switch (b) {
            case null -> numA.value().signum();
            case NumberItem numB -> numA.value().compareTo(numB.value());
            case QualifierItem _ -> 1; // numbers are newer than qualifiers: 1.0.1 > 1.0.alpha
          };
      case QualifierItem qualA ->
          switch (b) {
            case null -> Integer.compare(qualifierRank(qualA.value()), qualifierRank(""));
            case NumberItem _ -> -1;
            case QualifierItem qualB -> {
              int rankCompare =
                  Integer.compare(qualifierRank(qualA.value()), qualifierRank(qualB.value()));
              if (rankCompare != 0) yield rankCompare;
              yield qualifierRank(qualA.value()) == 8 ? qualA.value().compareTo(qualB.value()) : 0;
            }
          };
    };
  }

  private sealed interface VersionItem permits NumberItem, QualifierItem {}

  private record NumberItem(BigInteger value) implements VersionItem {}

  private record QualifierItem(String value) implements VersionItem {}
}
