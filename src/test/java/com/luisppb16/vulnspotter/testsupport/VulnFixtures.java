/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.testsupport;

import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.model.Ecosystem;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import java.util.List;
import java.util.Map;

/**
 * Factory of {@code OsvVulnerability} / {@code OsvPackage} / {@code ScanResult} test fixtures so
 * tests never use in-production compatibility constructors: with this factory, every test builds
 * its records through the canonical (Jackson-shaped) constructors in one readable call, and the
 * values preset here match the values the suites actually assert (9.8 → CRITICAL, 7.5 → HIGH, 5.6 →
 * MEDIUM, 3.5 → LOW, MODERATE → MEDIUM, no severity → UNKNOWN).
 */
public final class VulnFixtures {

  /** The canonical 9.8 vector (Log4Shell-class RCE) used by several suites. */
  public static final String CVSS_V3_9_8_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

  private VulnFixtures() {
    throw new UnsupportedOperationException("Utility class");
  }

  /** Canonical-shaped vulnerability with {@code withdrawn/published/modified} null. */
  public static OsvVulnerability vuln(
      String id,
      String summary,
      String details,
      List<OsvVulnerability.Severity> severity,
      List<OsvVulnerability.Affected> affected,
      List<OsvVulnerability.Reference> references,
      Map<String, Object> databaseSpecific) {
    return new OsvVulnerability(
        id,
        summary,
        details,
        null,
        null,
        null,
        null,
        severity,
        affected,
        references,
        databaseSpecific);
  }

  /** Vulnerability whose only severity data is a {@code database_specific.severity} label. */
  public static OsvVulnerability dbSeverity(String id, String severity) {
    return vuln(
        id,
        "Test vulnerability",
        "Description",
        null,
        List.of(),
        List.of(),
        Map.of("severity", severity));
  }

  /** Vulnerability carrying one CVSS_V3 plain score (e.g. "8.5"). */
  public static OsvVulnerability cvss(String id, String score) {
    return vuln(
        id,
        "Test vulnerability",
        "Description",
        List.of(new OsvVulnerability.Severity("CVSS_V3", score)),
        List.of(),
        List.of(),
        Map.of());
  }

  /** Vulnerability carrying one CVSS_V3 vector string (canonical e.g. Log4Shell 9.8). */
  public static OsvVulnerability vectorCritical(String id) {
    return vuln(
        id,
        "RCE",
        "Remote code execution",
        List.of(new OsvVulnerability.Severity("CVSS_V3", CVSS_V3_9_8_CRITICAL)),
        List.of(),
        List.of(),
        Map.of());
  }

  /** Vulnerability with no severity information at all. */
  public static OsvVulnerability noSeverity(String id) {
    return vuln(id, "Test vulnerability", "Description", null, List.of(), List.of(), Map.of());
  }

  /** ECOSYSTEM range with introduced "0" and the given fixed event (null ⇒ unfixed). */
  public static OsvVulnerability.Affected affected(String packageName, String fixed) {
    return new OsvVulnerability.Affected(
        new OsvVulnerability.Package(packageName, Ecosystem.MAVEN, null),
        List.of(
            new OsvVulnerability.Range(
                "ECOSYSTEM", List.of(new OsvVulnerability.Event("0", fixed, null, null)))),
        null,
        null);
  }

  /** A {@link Ecosystem#MAVEN Maven} package fixture. */
  public static OsvPackage pkg(String name, String version) {
    return new OsvPackage(name, Ecosystem.MAVEN, version);
  }

  /** A scan result over the given vulnerabilities (vulnerable iff one is given). */
  public static VulnerabilityScannerService.ScanResult result(
      OsvPackage pkg, boolean vulnerable, OsvVulnerability... vulnerabilities) {
    return new VulnerabilityScannerService.ScanResult(pkg, vulnerable, List.of(vulnerabilities));
  }
}
