/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.service;

import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import java.util.List;
import java.util.Locale;
import us.springett.cvss.Cvss;

/**
 * Shared logic for determining vulnerability severity from OSV data.
 *
 * <p>OSV publishes {@code severity[].score} as a full CVSS vector string (e.g. {@code
 * "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}), so the base score is computed from the vector.
 * The canonical CVSS data takes precedence; {@code database_specific.severity} is only used as a
 * fallback, and {@link #UNKNOWN} is returned when no severity information exists at all.
 *
 * <p>Stateless and thread-safe.
 */
public final class SeverityAnalyzer {

  public static final String CRITICAL = "CRITICAL";
  public static final String HIGH = "HIGH";
  public static final String MEDIUM = "MEDIUM";
  public static final String LOW = "LOW";
  public static final String UNKNOWN = "UNKNOWN";
  public static final String SAFE = "SAFE";

  /** Preference order when a record carries several CVSS entries. */
  private static final List<String> CVSS_TYPE_PRIORITY = List.of("CVSS_V4", "CVSS_V3", "CVSS_V2");

  /** Determine severity of a vulnerability: CVSS first, then database_specific fallback. */
  public String getSeverity(OsvVulnerability vulnerability) {
    ScoreWithType best = getScoreWithType(vulnerability);
    if (best != null) {
      return getSeverityLevel(best.score(), best.type());
    }
    String dbSeverity = getSeverityFromDatabaseSpecific(vulnerability);
    return dbSeverity != null ? dbSeverity : UNKNOWN;
  }

  /**
   * Compute the CVSS base score of a vulnerability, or {@code null} if no CVSS entry could be
   * parsed. Entries are preferred by CVSS version (v4 &gt; v3 &gt; v2); among entries of the same
   * type the highest score wins.
   */
  public Double getBaseScore(OsvVulnerability vulnerability) {
    ScoreWithType best = getScoreWithType(vulnerability);
    return best != null ? best.score() : null;
  }

  /** The best CVSS score together with the CVSS type that produced it. */
  private ScoreWithType getScoreWithType(OsvVulnerability vulnerability) {
    if (vulnerability.severity() == null || vulnerability.severity().isEmpty()) {
      return null;
    }
    for (String type : CVSS_TYPE_PRIORITY) {
      Double best = null;
      for (OsvVulnerability.Severity entry : vulnerability.severity()) {
        if (!type.equals(entry.type())) {
          continue;
        }
        Double score = parseScoreValue(entry.score());
        if (score != null && (best == null || score > best)) {
          best = score;
        }
      }
      if (best != null) {
        return new ScoreWithType(best, type);
      }
    }
    return null;
  }

  /** Extract severity from the top-level or per-affected {@code database_specific.severity}. */
  private String getSeverityFromDatabaseSpecific(OsvVulnerability vulnerability) {
    if (vulnerability.databaseSpecific() != null) {
      Object severity = vulnerability.databaseSpecific().get("severity");
      if (severity instanceof String severityString && !severityString.isBlank()) {
        return normalizeSeverity(severityString);
      }
    }
    if (vulnerability.affected() != null) {
      for (OsvVulnerability.Affected affected : vulnerability.affected()) {
        if (affected.databaseSpecific() != null) {
          Object severity = affected.databaseSpecific().get("severity");
          if (severity instanceof String severityString && !severityString.isBlank()) {
            return normalizeSeverity(severityString);
          }
        }
      }
    }
    return null;
  }

  /** Map CVSS score to severity level, using v3 bands by default and v2 bands for CVSS_V2. */
  private String getSeverityLevel(double score, String cvssType) {
    if ("CVSS_V2".equals(cvssType)) {
      if (score >= 7.0) return HIGH;
      if (score >= 4.0) return MEDIUM;
      return LOW;
    }
    return getSeverityLevel(score);
  }

  /** Parse a CVSS vector (or plain numeric score used by some non-standard feeds). */
  private static Double parseScoreValue(String rawScore) {
    if (rawScore == null || rawScore.isBlank()) {
      return null;
    }
    String trimmed = rawScore.trim();
    try {
      Cvss cvss = Cvss.fromVector(trimmed);
      if (cvss != null) {
        return cvss.calculateScore().getBaseScore();
      }
    } catch (RuntimeException e) {
      // Malformed vector; fall through to the plain-number fallback.
    }
    try {
      double value = Double.parseDouble(trimmed);
      return (value >= 0.0 && value <= 10.0) ? value : null;
    } catch (NumberFormatException e) {
      return null;
    }
  }

  /** Map CVSS score to severity level (CVSS v3 qualitative rating scale). */
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
      case "LOW", "MINIMAL", "NONE" -> LOW;
      default -> UNKNOWN;
    };
  }

  /** Get highest severity from a list of vulnerabilities. */
  public String getHighestSeverity(List<OsvVulnerability> vulnerabilities) {
    int maxLevel =
        (vulnerabilities == null || vulnerabilities.isEmpty())
            ? 0
            : vulnerabilities.stream()
                .map(this::getSeverity)
                .mapToInt(SeverityAnalyzer::severityToLevel)
                .max()
                .orElse(0);
    return levelToSeverity(maxLevel);
  }

  /** Map severity string to numeric level (higher = more severe). */
  public static int severityToLevel(String severity) {
    return switch (severity == null ? "" : severity) {
      case CRITICAL -> 5;
      case HIGH -> 4;
      case MEDIUM -> 3;
      case LOW -> 2;
      case UNKNOWN -> 1;
      default -> 0;
    };
  }

  /** Map numeric level to severity string. */
  private String levelToSeverity(int level) {
    return switch (level) {
      case 5 -> CRITICAL;
      case 4 -> HIGH;
      case 3 -> MEDIUM;
      case 2 -> LOW;
      case 1 -> UNKNOWN;
      default -> SAFE;
    };
  }

  private record ScoreWithType(double score, String type) {}
}
