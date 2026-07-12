/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.domain.service.FixedVersionResolver;
import com.luisppb16.vulnspotter.domain.service.SeverityAnalyzer;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/** Exports vulnerability reports into HTML, PDF, CSV, JSON, SARIF and Markdown files. */
public final class ReportExportService {

  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final SeverityAnalyzer SEVERITY_ANALYZER = new SeverityAnalyzer();
  private static final String TOOL_INFO_URI = "https://github.com/luisppb16";
  private static final String TOOL_VERSION = VulnerabilityReportBuilder.TOOL_VERSION;
  private static final String GENERATED_AT =
      OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

  private ReportExportService() {}

  public static void exportHtml(String html, Path outputPath) throws IOException {
    Files.writeString(outputPath, html, StandardCharsets.UTF_8);
  }

  public static void exportPdf(String html, Path outputPath) throws IOException {
    try (OutputStream outputStream = Files.newOutputStream(outputPath)) {
      PdfRendererBuilder builder = new PdfRendererBuilder();
      builder.useFastMode();
      builder.withHtmlContent(html, "file:///");
      builder.toStream(outputStream);
      builder.run();
    }
  }

  /** Generic Jackson serializer used internally (e.g. for the SARIF document). */
  static void writeJson(Object value, Path outputPath) throws IOException {
    String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value);
    Files.writeString(outputPath, json, StandardCharsets.UTF_8);
  }

  /**
   * Exports a structured JSON report: tool metadata, generation timestamp, roll-up summary and one
   * entry per scanned dependency with its full vulnerability breakdown (severity, CVSS, affected
   * ranges, fixed version, references).
   */
  public static void exportJsonReport(
      String projectName, List<VulnerabilityScannerService.ScanResult> scanResults, Path outputPath)
      throws IOException {
    List<VulnerabilityScannerService.ScanResult> results =
        scanResults == null ? List.of() : scanResults;
    long vulnerableDeps = results.stream().filter(VulnerabilityScannerService.ScanResult::vulnerable).count();
    long totalVulns =
        results.stream()
            .filter(VulnerabilityScannerService.ScanResult::vulnerable)
            .mapToLong(r -> r.vulnerabilities().size())
            .sum();

    ObjectNode root = MAPPER.createObjectNode();
    ObjectNode tool = root.putObject("tool");
    tool.put("name", "VulnSpotter");
    tool.put("version", TOOL_VERSION);
    tool.put("informationUri", TOOL_INFO_URI);
    tool.put("dataSource", "OSV.dev");
    root.put("project", projectName == null ? "" : projectName);
    root.put("generatedAt", GENERATED_AT);

    ObjectNode summary = root.putObject("summary");
    summary.put("totalDependencies", results.size());
    summary.put("vulnerableDependencies", vulnerableDeps);
    summary.put("totalVulnerabilities", totalVulns);

    ArrayNode resultsArr = root.putArray("results");
    for (VulnerabilityScannerService.ScanResult sr : results) {
      ObjectNode item = resultsArr.addObject();
      item.put("package", sr.pkg().name());
      item.put("version", sr.pkg().version());
      item.put("ecosystem", sr.pkg().ecosystem());
      item.put("vulnerable", sr.vulnerable());
      FixedVersionResolver.recommendUpgrade(
              sr.vulnerabilities(), sr.pkg().name(), sr.pkg().version())
          .ifPresent(fix -> item.put("recommendedFix", fix));
      ArrayNode vulnsArr = item.putArray("vulnerabilities");
      for (OsvVulnerability vuln : sr.vulnerabilities()) {
        ObjectNode v = vulnsArr.addObject();
        v.put("id", vuln.id());
        if (vuln.aliases() != null && !vuln.aliases().isEmpty()) {
          ArrayNode aliases = v.putArray("aliases");
          vuln.aliases().forEach(aliases::add);
        }
        String severity = SEVERITY_ANALYZER.getSeverity(vuln);
        v.put("severity", severity);
        Double score = SEVERITY_ANALYZER.getBaseScore(vuln);
        if (score != null) {
          v.put("cvssScore", score);
        }
        if (vuln.summary() != null && !vuln.summary().isBlank()) {
          v.put("summary", vuln.summary());
        }
        List<String> ranges = FixedVersionResolver.affectedRanges(vuln, sr.pkg().name());
        if (!ranges.isEmpty()) {
          ArrayNode r = v.putArray("affectedRanges");
          ranges.forEach(r::add);
        }
        v.put(
            "fixedVersion",
            FixedVersionResolver.resolve(vuln, sr.pkg().name(), sr.pkg().version()));
        if (vuln.references() != null && !vuln.references().isEmpty()) {
          ArrayNode refs = v.putArray("references");
          vuln.references().stream()
              .map(OsvVulnerability.Reference::url)
              .filter(u -> u != null && !u.isBlank())
              .forEach(refs::add);
        }
      }
    }
    writeJson(root, outputPath);
  }

  /**
   * CSV with one row per (dependency, vulnerability) so each finding is independently triageable.
   * A UTF-8 BOM is prepended so Excel opens it with the right encoding, and formula-injection
   * characters are neutralized.
   */
  public static void exportCsv(
      List<VulnerabilityScannerService.ScanResult> scanResults, Path outputPath)
      throws IOException {
    StringBuilder csv = new StringBuilder();
    csv.append(
        "Package,Version,Ecosystem,Vulnerability ID,CVE Aliases,Severity,CVSS,"
            + "Affected Range,Recommended Fix,Summary\r\n");
    for (VulnerabilityScannerService.ScanResult sr : scanResults) {
      String recommendedFix =
          sr.vulnerable()
              ? FixedVersionResolver.recommendUpgrade(
                      sr.vulnerabilities(), sr.pkg().name(), sr.pkg().version())
                  .orElse("")
              : "";
      if (!sr.vulnerable() || sr.vulnerabilities().isEmpty()) {
        csv.append(csvField(sr.pkg().name()))
            .append(',')
            .append(csvField(sr.pkg().version()))
            .append(',')
            .append(csvField(sr.pkg().ecosystem()))
            .append(',')
            .append("(none),,,,,,")
            .append(csvField(recommendedFix))
            .append(",\r\n");
        continue;
      }
      for (OsvVulnerability vuln : sr.vulnerabilities()) {
        String severity = SEVERITY_ANALYZER.getSeverity(vuln);
        Double score = SEVERITY_ANALYZER.getBaseScore(vuln);
        String cveAliases =
            vuln.aliases() == null
                ? ""
                : vuln.aliases().stream()
                    .filter(a -> a != null && a.toUpperCase(Locale.ROOT).startsWith("CVE-"))
                    .collect(Collectors.joining(" "));
        String ranges = String.join("; ", FixedVersionResolver.affectedRanges(vuln, sr.pkg().name()));
        csv.append(csvField(sr.pkg().name()))
            .append(',')
            .append(csvField(sr.pkg().version()))
            .append(',')
            .append(csvField(sr.pkg().ecosystem()))
            .append(',')
            .append(csvField(vuln.id() == null ? "" : vuln.id()))
            .append(',')
            .append(csvField(cveAliases))
            .append(',')
            .append(csvField(severity))
            .append(',')
            .append(score == null ? "" : String.format(Locale.ROOT, "%.1f", score))
            .append(',')
            .append(csvField(ranges))
            .append(',')
            .append(csvField(recommendedFix))
            .append(',')
            .append(csvField(vuln.summary() == null ? "" : vuln.summary()))
            .append("\r\n");
      }
    }
    // Prepend a UTF-8 BOM so spreadsheet apps decode it correctly.
    Files.writeString(outputPath, "\uFEFF" + csv, StandardCharsets.UTF_8);
  }

  /**
   * Quotes a CSV field and neutralizes spreadsheet formula injection (fields starting with =, +,
   * - or @ are prefixed with a single quote).
   */
  private static String csvField(String value) {
    String v = value == null ? "" : value;
    if (!v.isEmpty()) {
      char first = v.charAt(0);
      if (first == '=' || first == '+' || first == '-' || first == '@') {
        v = "'" + v;
      }
    }
    return "\"" + v.replace("\"", "\"\"") + "\"";
  }

  public static void exportSarif(
      List<VulnerabilityScannerService.ScanResult> scanResults, Path outputPath)
      throws IOException {
    ObjectNode sarif = MAPPER.createObjectNode();
    sarif.put("version", "2.1.0");
    sarif.put(
        "$schema",
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");

    ArrayNode runs = sarif.putArray("runs");
    ObjectNode run = runs.addObject();

    // Let consumers resolve artifact URIs against the project root.
    ObjectNode uriBases = run.putObject("originalUriBaseIds");
    ObjectNode srcRoot = uriBases.putObject("SRCROOT");
    srcRoot.put("uri", "file:///");

    ObjectNode tool = run.putObject("tool");
    ObjectNode driver = tool.putObject("driver");
    driver.put("name", "VulnSpotter");
    driver.put("version", TOOL_VERSION);
    driver.put("informationUri", TOOL_INFO_URI);
    ArrayNode rules = driver.putArray("rules");

    ObjectNode invocations = run.putArray("invocations").addObject();
    invocations.put("executionSuccessful", true);
    invocations.put("endTimeUtc", GENERATED_AT);

    Set<String> ruleIds = new LinkedHashSet<>();
    ArrayNode results = run.putArray("results");
    for (VulnerabilityScannerService.ScanResult sr : scanResults) {
      if (!sr.vulnerable()) continue;
      for (OsvVulnerability vuln : sr.vulnerabilities()) {
        String ruleId = vuln.id() != null ? vuln.id() : "unknown";
        if (ruleIds.add(ruleId)) {
          ObjectNode rule = rules.addObject();
          rule.put("id", ruleId);
          if (vuln.summary() != null && !vuln.summary().isBlank()) {
            rule.putObject("shortDescription").put("text", vuln.summary());
          }
          rule.put("helpUri", "https://osv.dev/vulnerability/" + ruleId);
        }

        ObjectNode result = results.addObject();
        result.put("ruleId", ruleId);
        ObjectNode message = result.putObject("message");
        message.put(
            "text",
            vuln.summary() != null
                ? sr.pkg().name() + ": " + vuln.summary()
                : sr.pkg().name() + " has vulnerability " + ruleId);
        result.put("level", sarifLevel(SEVERITY_ANALYZER.getSeverity(vuln)));

        ObjectNode location = result.putArray("locations").addObject();
        ObjectNode physicalLocation = location.putObject("physicalLocation");
        ObjectNode artifactLocation = physicalLocation.putObject("artifactLocation");
        artifactLocation.put("uri", manifestFileFor(sr.pkg().ecosystem()));
        artifactLocation.put("uriBaseId", "SRCROOT");
        ObjectNode region = physicalLocation.putObject("region");
        region.put("startLine", 1);

        ObjectNode properties = result.putObject("properties");
        properties.put("package", sr.pkg().name());
        properties.put("installedVersion", sr.pkg().version());
        properties.put("ecosystem", sr.pkg().ecosystem());
        FixedVersionResolver.recommendUpgrade(
                List.of(vuln), sr.pkg().name(), sr.pkg().version())
            .ifPresent(fix -> properties.put("recommendedFix", fix));
        List<String> ranges = FixedVersionResolver.affectedRanges(vuln, sr.pkg().name());
        if (!ranges.isEmpty()) {
          properties.put("affectedRange", String.join(", ", ranges));
        }
        if (vuln.aliases() != null && !vuln.aliases().isEmpty()) {
          ArrayNode aliases = properties.putArray("aliases");
          vuln.aliases().forEach(aliases::add);
        }
      }
    }

    writeJson(sarif, outputPath);
  }

  /** Plain Markdown report for pasting into PRs, wikis or issues. */
  public static void exportMarkdown(
      String projectName, List<VulnerabilityScannerService.ScanResult> scanResults, Path outputPath)
      throws IOException {
    List<VulnerabilityScannerService.ScanResult> results =
        scanResults == null ? List.of() : scanResults;
    long vulnerableDeps = results.stream().filter(VulnerabilityScannerService.ScanResult::vulnerable).count();
    long totalVulns =
        results.stream()
            .filter(VulnerabilityScannerService.ScanResult::vulnerable)
            .mapToLong(r -> r.vulnerabilities().size())
            .sum();

    StringBuilder md = new StringBuilder();
    md.append("# VulnSpotter Vulnerability Report\n\n");
    md.append("- **Project:** ").append(projectName == null ? "" : projectName).append('\n');
    md.append("- **Generated:** ").append(GENERATED_AT).append('\n');
    md.append("- **Tool:** VulnSpotter v").append(TOOL_VERSION).append(" (OSV.dev)\n");
    md.append("- **Dependencies scanned:** ").append(results.size()).append('\n');
    md.append("- **Vulnerable dependencies:** ").append(vulnerableDeps).append('\n');
    md.append("- **Vulnerabilities found:** ").append(totalVulns).append("\n\n");

    if (vulnerableDeps == 0) {
      md.append("No known vulnerabilities found in scanned dependencies.\n");
      Files.writeString(outputPath, md.toString(), StandardCharsets.UTF_8);
      return;
    }

    for (VulnerabilityScannerService.ScanResult sr : results) {
      if (!sr.vulnerable()) continue;
      String fix =
          FixedVersionResolver.recommendUpgrade(
                  sr.vulnerabilities(), sr.pkg().name(), sr.pkg().version())
              .orElse("Unknown");
      md.append("## `")
          .append(sr.pkg().name())
          .append("` @ ")
          .append(sr.pkg().version())
          .append("  (")
          .append(sr.pkg().ecosystem())
          .append(")\n");
      md.append("Recommended fix: **").append(fix).append("**\n\n");
      for (OsvVulnerability vuln : sr.vulnerabilities()) {
        String severity = SEVERITY_ANALYZER.getSeverity(vuln);
        Double score = SEVERITY_ANALYZER.getBaseScore(vuln);
        md.append("- **[").append(vuln.id()).append("](https://osv.dev/vulnerability/")
            .append(vuln.id())
            .append(")** — ")
            .append(severity);
        if (score != null) {
          md.append(" (CVSS ").append(String.format(Locale.ROOT, "%.1f", score)).append(")");
        }
        List<String> ranges = FixedVersionResolver.affectedRanges(vuln, sr.pkg().name());
        if (!ranges.isEmpty()) {
          md.append(" — affected: `").append(String.join(", ", ranges)).append("`");
        }
        if (vuln.summary() != null && !vuln.summary().isBlank()) {
          md.append(" — ").append(vuln.summary());
        }
        md.append('\n');
      }
      md.append('\n');
    }
    Files.writeString(outputPath, md.toString(), StandardCharsets.UTF_8);
  }

  private static String sarifLevel(String severity) {
    return switch (severity == null ? "" : severity) {
      case SeverityAnalyzer.CRITICAL, SeverityAnalyzer.HIGH -> "error";
      case SeverityAnalyzer.MEDIUM -> "warning";
      case SeverityAnalyzer.LOW -> "note";
      default -> "warning";
    };
  }

  /** Best-effort manifest file path so SARIF consumers have a real artifact to anchor to. */
  private static String manifestFileFor(String ecosystem) {
    return switch (ecosystem == null ? "" : ecosystem) {
      case "Maven" -> "pom.xml";
      case "npm" -> "package.json";
      case "PyPI" -> "requirements.txt";
      case "Go" -> "go.mod";
      default -> "dependencies";
    };
  }
}