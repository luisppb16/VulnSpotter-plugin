/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.service;

import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.List;
import java.util.Locale;

/** Shared logic for determining vulnerability severity from OSV data. */
public final class SeverityAnalyzer {

  private static final String CRITICAL = "CRITICAL";
  private static final String HIGH = "HIGH";
  private static final String MEDIUM = "MEDIUM";
  private static final String LOW = "LOW";
  private final NumberFormat numberFormat;

  public SeverityAnalyzer() {
    this.numberFormat = NumberFormat.getInstance(Locale.ROOT);
  }

  /** Determine severity of a vulnerability, checking database_specific first, then CVSS. */
  public String getSeverity(OsvVulnerability vulnerability) {
    String dbSeverity = getSeverityFromDatabaseSpecific(vulnerability);
    if (dbSeverity != null) {
      return dbSeverity;
    }
    return getSeverityFromCvss(vulnerability);
  }

  /** Extract severity from database_specific field (if present). */
  private String getSeverityFromDatabaseSpecific(OsvVulnerability vulnerability) {
    if (vulnerability.databaseSpecific() != null) {
      Object severity = vulnerability.databaseSpecific().get("severity");
      if (severity instanceof String severityString && !severityString.isBlank()) {
        return normalizeSeverity(severityString);
      }
    }
    return null;
  }

  /** Extract severity from CVSS score (V2 or V3). */
  private String getSeverityFromCvss(OsvVulnerability vulnerability) {
    if (vulnerability.severity() == null) {
      return MEDIUM;
    }
    return vulnerability.severity().stream()
        .filter(s -> "CVSS_V3".equals(s.type()) || "CVSS_V2".equals(s.type()))
        .map(s -> new SeverityScore(parseScoreValue(s.score()), s.type()))
        .filter(s -> s.score() > 0)
        .map(s -> getSeverityLevel(s.score()))
        .findFirst()
        .orElse(MEDIUM);
  }

  private double parseScoreValue(String rawScore) {
    if (rawScore == null || rawScore.isBlank()) {
      return -1;
    }
    try {
      return numberFormat.parse(rawScore).doubleValue();
    } catch (ParseException | NumberFormatException e) {
      return -1;
    }
  }

  /** Map CVSS score to severity level. */
  private String getSeverityLevel(double score) {
    if (score >= 9.0) return CRITICAL;
    if (score >= 7.0) return HIGH;
    if (score >= 4.0) return MEDIUM;
    return LOW;
  }

  /** Normalize raw severity string to standard levels. */
  private String normalizeSeverity(String rawSeverity) {
    String severity = rawSeverity.toUpperCase(Locale.ROOT);
    return switch (severity) {
      case "CRITICAL" -> CRITICAL;
      case "HIGH", "IMPORTANT" -> HIGH;
      case "MEDIUM", "MODERATE" -> MEDIUM;
      case "LOW" -> LOW;
      default -> MEDIUM;
    };
  }

  /** Get highest severity from a list of vulnerabilities. */
  public String getHighestSeverity(List<OsvVulnerability> vulnerabilities) {
    int maxLevel =
        (vulnerabilities == null || vulnerabilities.isEmpty())
            ? 0
            : vulnerabilities.stream()
                .map(this::getSeverity)
                .mapToInt(this::severityToLevel)
                .max()
                .orElse(0);
    return levelToSeverity(maxLevel);
  }

  /** Map severity string to numeric level. */
  private int severityToLevel(String severity) {
    return switch (severity) {
      case CRITICAL -> 4;
      case HIGH -> 3;
      case MEDIUM -> 2;
      case LOW -> 1;
      default -> 0;
    };
  }

  /** Map numeric level to severity string. */
  private String levelToSeverity(int level) {
    return switch (level) {
      case 4 -> CRITICAL;
      case 3 -> HIGH;
      case 2 -> MEDIUM;
      case 1 -> LOW;
      default -> "SAFE";
    };
  }

  private record SeverityScore(double score, String source) {}
}
