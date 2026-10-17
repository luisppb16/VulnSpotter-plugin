/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.testsupport.VulnFixtures;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SeverityAnalyzer Test Suite")
class SeverityAnalyzerTest {

  @Test
  @DisplayName("should_extract_severity_from_database_specific")
  void shouldExtractFromDatabaseSpecific() {
    // Given
    OsvVulnerability vuln = VulnFixtures.dbSeverity("CVE-2024-001", "HIGH");

    // When
    String severity = SeverityAnalyzer.getSeverity(vuln);

    // Then
    assertThat(severity).isEqualTo("HIGH");
  }

  @Test
  @DisplayName("should_extract_severity_from_cvss_v3")
  void shouldExtractFromCvssV3() {
    // Given
    OsvVulnerability vuln = VulnFixtures.cvss("CVE-2024-002", "8.5");

    // When
    String severity = SeverityAnalyzer.getSeverity(vuln);

    // Then
    assertThat(severity).isEqualTo("HIGH");
  }

  @Test
  @DisplayName("should_return_unknown_when_no_severity")
  void shouldReturnUnknownWhenNoSeverity() {
    // Given
    OsvVulnerability vuln = VulnFixtures.noSeverity("CVE-2024-003");

    // When
    String severity = SeverityAnalyzer.getSeverity(vuln);

    // Then: no CVSS and no database_specific.severity → UNKNOWN (kept visible regardless of the
    // minimum-severity threshold, see VulnerabilityScannerService#applySettingsFilters).
    assertThat(severity).isEqualTo("UNKNOWN");
  }

  @Test
  @DisplayName("should_get_highest_severity_from_list")
  void shouldGetHighestFromList() {
    // Given
    OsvVulnerability low = VulnFixtures.cvss("CVE-LOW", "3.5");
    OsvVulnerability high = VulnFixtures.cvss("CVE-HIGH", "8.0");

    // When
    String highest = SeverityAnalyzer.getHighestSeverity(List.of(low, high));

    // Then
    assertThat(highest).isEqualTo("HIGH");
  }

  @Test
  @DisplayName("should_parse_real_cvss_v3_vector_as_critical")
  void shouldParseRealCvssV3Vector() {
    // Given: the canonical 9.8 vector (e.g. Log4Shell-class RCE)
    OsvVulnerability vuln = VulnFixtures.vectorCritical("CVE-2021-44228");

    // When / Then
    assertThat(SeverityAnalyzer.getSeverity(vuln)).isEqualTo(SeverityAnalyzer.CRITICAL);
    assertThat(SeverityAnalyzer.getBaseScore(vuln)).isEqualTo(9.8);
  }

  @Test
  @DisplayName("should_prefer_cvss_vector_over_database_specific_label")
  void shouldPreferCvssOverDatabaseSpecific() {
    // Given: GHSA label says LOW but the actual vector is a 7.5 HIGH
    OsvVulnerability vuln =
        VulnFixtures.vuln(
            "CVE-2024-005",
            "Test",
            "Test",
            List.of(
                new OsvVulnerability.Severity(
                    "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")),
            List.of(),
            List.of(),
            Map.of("severity", "LOW"));

    // When / Then
    assertThat(SeverityAnalyzer.getSeverity(vuln)).isEqualTo(SeverityAnalyzer.HIGH);
  }

  @Test
  @DisplayName("should_prefer_v4_over_v3_when_both_present")
  void shouldPreferV4OverV3() {
    // Given: a v3 CRITICAL alongside a v4 vector that scores lower — v4 wins.
    OsvVulnerability vuln =
        VulnFixtures.vuln(
            "CVE-2024-006",
            "Test",
            "Test",
            List.of(
                new OsvVulnerability.Severity(
                    "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                new OsvVulnerability.Severity(
                    "CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")),
            List.of(),
            List.of(),
            Map.of());

    // When
    Double score = SeverityAnalyzer.getBaseScore(vuln);

    // Then: score comes from the v4 vector, not the 9.8 v3 one.
    assertThat(score).isNotNull();
    assertThat(score).isLessThan(9.8);
  }

  @Test
  @DisplayName("should_parse_cvss_v2_vector")
  void shouldParseCvssV2Vector() {
    // Given
    OsvVulnerability vuln =
        VulnFixtures.vuln(
            "CVE-2015-0001",
            "Old",
            "Old",
            List.of(new OsvVulnerability.Severity("CVSS_V2", "AV:N/AC:L/Au:N/C:P/I:P/A:P")),
            List.of(),
            List.of(),
            Map.of());

    // When / Then: 7.5 in v2 maps to HIGH.
    assertThat(SeverityAnalyzer.getBaseScore(vuln)).isEqualTo(7.5);
    assertThat(SeverityAnalyzer.getSeverity(vuln)).isEqualTo(SeverityAnalyzer.HIGH);
  }

  @Test
  @DisplayName("should_normalize_moderate_to_medium")
  void shouldNormalizeModerate() {
    // Given
    OsvVulnerability vuln = VulnFixtures.dbSeverity("CVE-2024-004", "MODERATE");

    // When
    String severity = SeverityAnalyzer.getSeverity(vuln);

    // Then
    assertThat(severity).isEqualTo("MEDIUM");
  }
}
