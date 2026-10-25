/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.service;

import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Resolves the recommended fixed version and the version branches (windows) of a vulnerability
 * affecting a scanned package.
 *
 * <p>Only {@code ECOSYSTEM} and {@code SEMVER} ranges are considered: {@code GIT} ranges carry
 * commit hashes as "fixed" events, which must never be surfaced as upgrade targets.
 */
public final class FixedVersionResolver {

  public static final String UNKNOWN = "Unknown";

  private FixedVersionResolver() {}

  /**
   * Returns the recommended fixed version for the given vulnerability and package: the fixed
   * version of the branch containing the current one (smallest above it, same-major preferred), the
   * best global fix when no marked branch carries one, or all known fixed versions joined with
   * commas when none is strictly greater, or {@link #UNKNOWN} when the record has no usable fixed
   * events.
   */
  public static String resolve(OsvVulnerability vuln, String packageName, String currentVersion) {
    if (vuln == null || vuln.affected() == null) {
      return UNKNOWN;
    }
    List<AffectedWindow> windows =
        windowsFrom(applicableRanges(vuln, packageName).toList(), currentVersion);
    return fixForInstalledBranch(windows, currentVersion);
  }

  /** All distinct fixed versions declared for the package in ECOSYSTEM/SEMVER ranges. */
  public static List<String> fixedVersions(OsvVulnerability vuln, String packageName) {
    if (vuln == null || vuln.affected() == null) {
      return List.of();
    }
    return fixes(windowsFrom(applicableRanges(vuln, packageName).toList(), null));
  }

  /**
   * The single version that remediates all the given vulnerabilities for a package: the fix of the
   * installed version's branch across all advisories when any advisory fixes that branch, and only
   * otherwise the highest of the per-vulnerability recommended fixes. Empty when no vulnerability
   * has a usable fix.
   */
  public static Optional<String> recommendUpgrade(
      Collection<OsvVulnerability> vulnerabilities, String packageName, String currentVersion) {
    if (vulnerabilities == null) {
      return Optional.empty();
    }
    List<String> installedBranchFixes = new ArrayList<>();
    for (OsvVulnerability vuln : vulnerabilities) {
      if (vuln == null || vuln.affected() == null) {
        continue;
      }
      windowsFrom(applicableRanges(vuln, packageName).toList(), currentVersion).stream()
          .filter(w -> w.containsInstalledVersion())
          .map(AffectedWindow::fixedVersion)
          .filter(Objects::nonNull)
          .distinct()
          .forEach(installedBranchFixes::add);
    }
    if (!installedBranchFixes.isEmpty()) {
      return Optional.ofNullable(
          VersionUtil.findBestFixedVersion(installedBranchFixes, currentVersion));
    }
    String best = null;
    for (OsvVulnerability vuln : vulnerabilities) {
      List<String> fixes = fixedVersions(vuln, packageName);
      if (fixes.isEmpty()) {
        continue;
      }
      String fixed = VersionUtil.findBestFixedVersion(fixes, currentVersion);
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
   * is intentionally <b>not</b> accepted: a vulnerability on {@code org.evil:jackson-core} must
   * never be attributed to {@code com.fasterxml.jackson.core:jackson-core}. The {@code
   * group:artifact} suffix check still lets a bare scanned name match a grouped OSV name (and vice
   * versa).
   */
  public static boolean isMatchingPackage(String scannedPkg, String vulnPkg) {
    if (scannedPkg == null || vulnPkg == null) return false;
    if (scannedPkg.equals(vulnPkg)) return true;
    if (vulnPkg.endsWith(":" + scannedPkg)) return true;
    return scannedPkg.endsWith(":" + vulnPkg);
  }

  /**
   * Human-readable affected ranges for the package in a vulnerability, one text per version branch:
   * {@code ">=1.0.0, <1.2.3"} or {@code ">=1.0.0, up to 1.1.0"}. Multi-branch records keep every
   * window instead of collapsing to the last one.
   */
  public static List<String> affectedRanges(OsvVulnerability vuln, String packageName) {
    if (vuln == null || vuln.affected() == null) {
      return List.of();
    }
    return rangeTexts(windowsFrom(applicableRanges(vuln, packageName).toList(), null));
  }

  /**
   * {@link #resolve} and {@link #affectedRanges} walk the same applicable ranges; card rendering
   * (details cards in the tool window, exports) needs the pair per record and derives it from one
   * pass instead of walking {@code vuln.affected()} twice.
   */
  public static Resolution resolveWithRanges(
      OsvVulnerability vuln, String packageName, String currentVersion) {
    if (vuln == null || vuln.affected() == null) {
      return new Resolution(UNKNOWN, List.of(), List.of());
    }
    List<AffectedWindow> windows =
        windowsFrom(applicableRanges(vuln, packageName).toList(), currentVersion);
    return new Resolution(
        fixForInstalledBranch(windows, currentVersion), rangeTexts(windows), windows);
  }

  /** The fixed versions of the branches that contain the installed version, best first. */
  private static String fixForInstalledBranch(List<AffectedWindow> windows, String installed) {
    if (windows.isEmpty()) {
      return UNKNOWN;
    }
    List<String> containing =
        windows.stream()
            .filter(AffectedWindow::containsInstalledVersion)
            .map(AffectedWindow::fixedVersion)
            .filter(Objects::nonNull)
            .distinct()
            .toList();
    if (!containing.isEmpty()) {
      return VersionUtil.findBestFixedVersion(containing, installed);
    }
    List<String> all = fixes(windows);
    if (all.isEmpty()) {
      return UNKNOWN;
    }
    if (installed == null || installed.isBlank()) {
      return String.join(", ", all);
    }
    String best = VersionUtil.findBestFixedVersion(all, installed);
    return best != null ? best : String.join(", ", all);
  }

  private static List<String> fixes(List<AffectedWindow> windows) {
    return windows.stream()
        .map(AffectedWindow::fixedVersion)
        .filter(Objects::nonNull)
        .distinct()
        .toList();
  }

  private static List<String> rangeTexts(List<AffectedWindow> windows) {
    return windows.stream().map(AffectedWindow::rangeText).distinct().toList();
  }

  /**
   * The ECOSYSTEM/SEMVER ranges declared for this package — the shared prefix of {@code
   * fixedVersions} and {@code affectedRanges}; other range kinds carry no actionable versions.
   */
  private static Stream<OsvVulnerability.Range> applicableRanges(
      OsvVulnerability vuln, String packageName) {
    return vuln.affected().stream()
        .filter(a -> a.pkg() != null && isMatchingPackage(packageName, a.pkg().name()))
        .filter(a -> a.ranges() != null)
        .flatMap(a -> a.ranges().stream())
        .filter(r -> "ECOSYSTEM".equalsIgnoreCase(r.type()) || "SEMVER".equalsIgnoreCase(r.type()));
  }

  /**
   * Segments each range's ordered events into windows: an {@code introduced} event opens a window
   * (and closes the previous one), a {@code fixed}/{@code last_affected}/{@code limit} event closes
   * it and is emitted. Events after the last closing event reopen a window that stays open without
   * a fix. A {@code fixed} close is exclusive, {@code last_affected} inclusive, {@code limit}
   * exclusive and approximate (it never yields a fixed version).
   */
  private static List<AffectedWindow> windowsFrom(
      Collection<OsvVulnerability.Range> ranges, String installed) {
    List<AffectedWindow> windows = new ArrayList<>();
    for (OsvVulnerability.Range range : ranges) {
      if (range == null || range.events() == null || range.events().isEmpty()) {
        continue;
      }
      String introduced = null;
      String fixed = null;
      String lastAffected = null;
      String limit = null;
      for (OsvVulnerability.Event event : range.events()) {
        if (event == null) {
          continue;
        }
        String reopened = nonBlank(event.introduced());
        if (reopened != null && introduced != null) {
          windows.add(window(introduced, fixed, lastAffected, limit, installed));
          fixed = null;
          lastAffected = null;
          limit = null;
        }
        if (reopened != null) {
          introduced = reopened;
        }
        String f = nonBlank(event.fixed());
        String la = nonBlank(event.lastAffected());
        String lim = nonBlank(event.limit());
        if (f != null || la != null || lim != null) {
          if (f != null) {
            fixed = f;
          }
          if (la != null) {
            lastAffected = la;
          }
          if (lim != null) {
            limit = lim;
          }
          windows.add(window(introduced, fixed, lastAffected, limit, installed));
          introduced = null;
          fixed = null;
          lastAffected = null;
          limit = null;
        }
      }
      if (introduced != null) {
        windows.add(window(introduced, null, null, null, installed));
      }
    }
    return List.copyOf(new LinkedHashSet<>(windows));
  }

  /** Opens at {@code introduced} (normalised to {@code "0"} when absent) with the given closes. */
  private static AffectedWindow window(
      String introduced, String fixed, String lastAffected, String limit, String installed) {
    String intro = (introduced == null || introduced.isBlank()) ? "0" : introduced;
    String fix = (fixed == null || fixed.isBlank()) ? null : fixed;
    return new AffectedWindow(
        intro,
        fix,
        formatWindow(intro, fixed, lastAffected, limit),
        branchLabel(intro),
        containsInstalled(intro, fix, lastAffected, limit, installed));
  }

  private static boolean containsInstalled(
      String intro, String fixed, String lastAffected, String limit, String installed) {
    if (installed == null || installed.isBlank()) {
      return false;
    }
    if (VersionUtil.compareVersions(installed, intro) < 0) {
      return false;
    }
    if (fixed != null) {
      return VersionUtil.compareVersions(installed, fixed) < 0;
    }
    if (lastAffected != null) {
      return VersionUtil.compareVersions(installed, lastAffected) <= 0;
    }
    if (limit != null) {
      return VersionUtil.compareVersions(installed, limit) < 0;
    }
    return true;
  }

  private static String formatWindow(
      String intro, String fixed, String lastAffected, String limit) {
    StringBuilder sb = new StringBuilder();
    sb.append(">=").append(intro);
    if (fixed != null) {
      sb.append(", <").append(fixed);
    } else if (lastAffected != null) {
      sb.append(", up to ").append(lastAffected);
    } else if (limit != null) {
      sb.append(", <").append(limit).append(" (approx.)");
    }
    return sb.toString();
  }

  /**
   * "3.0.0" → "Branch 3.0.x", "2.8.0-alpha" → "Branch 2.8.x", "3" → "Branch 3.x"; {@code null} for
   * the open-ended "0" introduction (every release).
   */
  private static String branchLabel(String intro) {
    if (intro == null || intro.isBlank()) {
      return null;
    }
    List<String> numeric = new ArrayList<>();
    for (String segment : intro.split("\\.")) {
      if (!segment.matches("\\d+")) {
        break;
      }
      numeric.add(segment);
    }
    if (numeric.isEmpty()) {
      return null;
    }
    String kept =
        numeric.size() > 1
            ? String.join(".", numeric.subList(0, numeric.size() - 1))
            : numeric.getFirst();
    return "Branch " + kept + ".x";
  }

  private static String nonBlank(String value) {
    return value == null || value.isBlank() ? null : value.strip();
  }

  /**
   * A single affected version branch (window): opens at {@code introduced} and closes at {@code
   * fixedVersion} when the branch has a fix, at {@code last_affected}/{@code limit} otherwise, or
   * stays open. {@code rangeText} is the rendered range; {@code containsInstalledVersion} marks the
   * branch the scanned version actually falls into.
   */
  public record AffectedWindow(
      String introduced,
      String fixedVersion,
      String rangeText,
      String branchLabel,
      boolean containsInstalledVersion) {}

  /** Recommended fix plus affected branches, for renderers that need the pair. */
  public record Resolution(
      String fixedVersion, List<String> affectedRanges, List<AffectedWindow> branches) {}
}
