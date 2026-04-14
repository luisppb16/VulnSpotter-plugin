/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.VulnSpotter.util;

import java.util.List;

public class VersionUtil {

  /**
   * Finds the best fixed version from a list of fixed versions, given the current version. The best
   * fixed version is the smallest version that is strictly greater than the current version and
   * ideally in the same major branch.
   *
   * @param fixedVersions List of fixed versions for the package.
   * @param currentVersion The current version of the package.
   * @return The best fixed version, or null if none is strictly greater.
   */
  public static String findBestFixedVersion(List<String> fixedVersions, String currentVersion) {
    if (fixedVersions == null || fixedVersions.isEmpty()) return null;
    if (currentVersion == null || currentVersion.isBlank()) return fixedVersions.get(0);

    String bestVersion = null;
    boolean bestIsSameMajor = false;

    for (String fixed : fixedVersions) {
      if (fixed == null || fixed.isBlank()) continue;

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

    // Fallback: if we didn't find any strictly greater, just return the first one

    return bestVersion;
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
   * Compares two version strings.
   *
   * @return a negative integer, zero, or a positive integer as v1 is less than, equal to, or
   *     greater than v2.
   */
  public static int compareVersions(String v1, String v2) {
    String[] p1 = v1.replaceAll("[^0-9a-zA-Z.]", ".").split("\\.");
    String[] p2 = v2.replaceAll("[^0-9a-zA-Z.]", ".").split("\\.");

    int length = Math.max(p1.length, p2.length);
    for (int i = 0; i < length; i++) {
      String part1 = i < p1.length ? p1[i] : "0";
      String part2 = i < p2.length ? p2[i] : "0";

      if (part1.isEmpty()) part1 = "0";
      if (part2.isEmpty()) part2 = "0";

      int comp;
      if (isNumeric(part1) && isNumeric(part2)) {
        long n1 = Long.parseLong(part1);
        long n2 = Long.parseLong(part2);
        comp = Long.compare(n1, n2);
      } else {
        comp = part1.compareToIgnoreCase(part2);
      }
      if (comp != 0) return comp;
    }
    return 0;
  }

  private static boolean isNumeric(String str) {
    for (char c : str.toCharArray()) {
      if (!Character.isDigit(c)) return false;
    }
    return true;
  }
}
