/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.vulnspotter.util;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulnspotter.model.OsvVulnerability;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SeverityAnalyzer Test Suite")
class SeverityAnalyzerTest {

  private SeverityAnalyzer analyzer;

  @BeforeEach
  void setUp() {
    analyzer = new SeverityAnalyzer();
  }

  @Test
  @DisplayName("should_extract_severity_from_database_specific")
  void shouldExtractFromDatabaseSpecific() {
    // Given
    OsvVulnerability vuln =
        new OsvVulnerability(
            "CVE-2024-001",
            "Test vulnerability",
            "Description",
            null,
            Collections.emptyList(),
            Collections.emptyList(),
            Map.of("severity", "HIGH"));

    // When
    String severity = analyzer.getSeverity(vuln);

    // Then
    assertThat(severity).isEqualTo("HIGH");
  }

  @Test
  @DisplayName("should_extract_severity_from_cvss_v3")
  void shouldExtractFromCvssV3() {
    // Given
    OsvVulnerability vuln =
        new OsvVulnerability(
            "CVE-2024-002",
            "Test vulnerability",
            "Description",
            List.of(new OsvVulnerability.Severity("CVSS_V3", "8.5")),
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyMap());

    // When
    String severity = analyzer.getSeverity(vuln);

    // Then
    assertThat(severity).isEqualTo("HIGH");
  }

  @Test
  @DisplayName("should_return_medium_when_no_severity")
  void shouldReturnMediumDefault() {
    // Given
    OsvVulnerability vuln =
        new OsvVulnerability(
            "CVE-2024-003",
            "Test vulnerability",
            "Description",
            null,
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyMap());

    // When
    String severity = analyzer.getSeverity(vuln);

    // Then
    assertThat(severity).isEqualTo("MEDIUM");
  }

  @Test
  @DisplayName("should_get_highest_severity_from_list")
  void shouldGetHighestFromList() {
    // Given
    OsvVulnerability low =
        new OsvVulnerability(
            "CVE-LOW",
            "Low",
            "Low",
            List.of(new OsvVulnerability.Severity("CVSS_V3", "3.5")),
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyMap());
    OsvVulnerability high =
        new OsvVulnerability(
            "CVE-HIGH",
            "High",
            "High",
            List.of(new OsvVulnerability.Severity("CVSS_V3", "8.0")),
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.emptyMap());

    // When
    String highest = analyzer.getHighestSeverity(List.of(low, high));

    // Then
    assertThat(highest).isEqualTo("HIGH");
  }

  @Test
  @DisplayName("should_normalize_moderate_to_medium")
  void shouldNormalizeModerate() {
    // Given
    OsvVulnerability vuln =
        new OsvVulnerability(
            "CVE-2024-004",
            "Test",
            "Test",
            null,
            Collections.emptyList(),
            Collections.emptyList(),
            Map.of("severity", "MODERATE"));

    // When
    String severity = analyzer.getSeverity(vuln);

    // Then
    assertThat(severity).isEqualTo("MEDIUM");
  }
}
