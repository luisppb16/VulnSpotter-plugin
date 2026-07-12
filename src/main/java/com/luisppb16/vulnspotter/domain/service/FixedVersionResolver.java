/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.service;

import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Resolves the recommended fixed version for a vulnerability affecting a scanned package.
 *
 * <p>Only {@code ECOSYSTEM} and {@code SEMVER} ranges are considered: {@code GIT} ranges carry
 * commit hashes as "fixed" events, which must never be surfaced as upgrade targets.
 */
public final class FixedVersionResolver {

  public static final String UNKNOWN = "Unknown";

  private FixedVersionResolver() {}

  /**
   * Returns the recommended fixed version for the given vulnerability and package: the smallest
   * fixed version above the current one (same-major preferred), or all known fixed versions joined
   * with commas when none is strictly greater, or {@link #UNKNOWN} when the record has no usable
   * fixed events.
   */
  public static String resolve(OsvVulnerability vuln, String packageName, String currentVersion) {
    List<String> fixedVersions = fixedVersions(vuln, packageName);
    if (fixedVersions.isEmpty()) {
      return UNKNOWN;
    }
    if (currentVersion == null || currentVersion.isBlank()) {
      return String.join(", ", fixedVersions);
    }
    String best = VersionUtil.findBestFixedVersion(fixedVersions, currentVersion);
    return best != null ? best : String.join(", ", fixedVersions);
  }

  /** All distinct fixed versions declared for the package in ECOSYSTEM/SEMVER ranges. */
  public static List<String> fixedVersions(OsvVulnerability vuln, String packageName) {
    if (vuln == null || vuln.affected() == null) {
      return List.of();
    }
    return vuln.affected().stream()
        .filter(a -> a.pkg() != null && isMatchingPackage(packageName, a.pkg().name()))
        .filter(a -> a.ranges() != null)
        .flatMap(a -> a.ranges().stream())
        .filter(r -> "ECOSYSTEM".equalsIgnoreCase(r.type()) || "SEMVER".equalsIgnoreCase(r.type()))
        .filter(r -> r.events() != null)
        .flatMap(r -> r.events().stream())
        .map(OsvVulnerability.Event::fixed)
        .filter(Objects::nonNull)
        .filter(v -> !v.isBlank())
        .distinct()
        .toList();
  }

  /**
   * The single version that remediates all the given vulnerabilities for a package: the highest of
   * the per-vulnerability recommended fixes. Empty when no vulnerability has a usable fix.
   */
  public static Optional<String> recommendUpgrade(
      Collection<OsvVulnerability> vulnerabilities, String packageName, String currentVersion) {
    if (vulnerabilities == null) {
      return Optional.empty();
    }
    String best = null;
    for (OsvVulnerability vuln : vulnerabilities) {
      String fixed = VersionUtil.findBestFixedVersion(
          fixedVersions(vuln, packageName), currentVersion);
      if (fixed == null) {
        continue;
      }
      if (best == null || VersionUtil.compareVersions(fixed, best) > 0) {
        best = fixed;
      }
    }
    return Optional.ofNullable(best);
  }

  /**
   * Match a scanned package name against the package name declared in an OSV record.
   *
   * <p>For group-aware ecosystems (Maven uses {@code group:artifact}) a bare artifactId-only match
   * is intentionally <b>not</b> accepted: a vulnerability on {@code org.evil:jackson-core} must never
   * be attributed to {@code com.fasterxml.jackson.core:jackson-core}. The {@code group:artifact}
   * suffix check still lets a bare scanned name match a grouped OSV name (and vice versa).
   */
  public static boolean isMatchingPackage(String scannedPkg, String vulnPkg) {
    if (scannedPkg == null || vulnPkg == null) return false;
    if (scannedPkg.equals(vulnPkg)) return true;
    if (vulnPkg.endsWith(":" + scannedPkg)) return true;
    if (scannedPkg.endsWith(":" + vulnPkg)) return true;
    return false;
  }

  /**
   * Human-readable affected ranges for the package in a vulnerability, derived from the
   * {@code introduced}/{@code fixed}/{@code last_affected} events of its ECOSYSTEM/SEMVER ranges.
   * Each entry looks like {@code ">=1.0.0, <1.2.3"} or {@code ">=1.0.0, up to 1.1.0"}.
   */
  public static List<String> affectedRanges(OsvVulnerability vuln, String packageName) {
    if (vuln == null || vuln.affected() == null) {
      return List.of();
    }
    return vuln.affected().stream()
        .filter(a -> a.pkg() != null && isMatchingPackage(packageName, a.pkg().name()))
        .filter(a -> a.ranges() != null)
        .flatMap(a -> a.ranges().stream())
        .filter(r -> "ECOSYSTEM".equalsIgnoreCase(r.type()) || "SEMVER".equalsIgnoreCase(r.type()))
        .filter(r -> r.events() != null && !r.events().isEmpty())
        .map(FixedVersionResolver::formatRange)
        .filter(s -> !s.isBlank())
        .distinct()
        .toList();
  }

  private static String formatRange(OsvVulnerability.Range range) {
    String introduced = null;
    String fixed = null;
    String lastAffected = null;
    for (OsvVulnerability.Event event : range.events()) {
      if (event.introduced() != null && !event.introduced().isBlank()) {
        introduced = event.introduced();
      }
      if (event.fixed() != null && !event.fixed().isBlank()) {
        fixed = event.fixed();
      }
      if (event.lastAffected() != null && !event.lastAffected().isBlank()) {
        lastAffected = event.lastAffected();
      }
    }
    StringBuilder sb = new StringBuilder();
    if (introduced != null) {
      sb.append(">=").append(introduced);
    }
    if (fixed != null) {
      if (!sb.isEmpty()) sb.append(", ");
      sb.append("<").append(fixed);
    } else if (lastAffected != null) {
      if (!sb.isEmpty()) sb.append(", ");
      sb.append("up to ").append(lastAffected);
    }
    return sb.toString();
  }
}
