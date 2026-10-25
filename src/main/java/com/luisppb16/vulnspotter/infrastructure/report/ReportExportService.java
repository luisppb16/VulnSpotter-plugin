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
import com.luisppb16.vulnspotter.domain.model.DependencyProvenance;
import com.luisppb16.vulnspotter.domain.model.Ecosystem;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.domain.service.FixedVersionResolver;
import com.luisppb16.vulnspotter.domain.service.SeverityAnalyzer;
import com.luisppb16.vulnspotter.infrastructure.osv.ProjectConstants;
import com.luisppb16.vulnspotter.util.Json;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** Exports vulnerability reports into HTML, PDF, CSV, JSON, SARIF and Markdown files. */
public final class ReportExportService {

  private static final ObjectMapper MAPPER = Json.MAPPER;
  private static final String TOOL_INFO_URI = "https://github.com/luisppb16";
  private static final String TOOL_VERSION = VulnerabilityReportBuilder.TOOL_VERSION;

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
  private static void writeJson(Object value, Path outputPath) throws IOException {
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
    VulnerabilityScannerService.ScanSummary rollUp =
        VulnerabilityScannerService.ScanSummary.of(results);

    ObjectNode root = MAPPER.createObjectNode();
    ObjectNode tool = root.putObject("tool");
    tool.put("name", "VulnSpotter");
    tool.put("version", TOOL_VERSION);
    tool.put("informationUri", TOOL_INFO_URI);
    tool.put("dataSource", "OSV.dev");
    root.put("project", projectName == null ? "" : projectName);
    root.put("generatedAt", VulnerabilityReportBuilder.nowTimestamp());

    ObjectNode summary = root.putObject("summary");
    summary.put("totalDependencies", rollUp.scanned());
    summary.put("vulnerableDependencies", rollUp.vulnerable());
    summary.put("totalVulnerabilities", rollUp.totalVulnerabilities());

    ArrayNode resultsArr = root.putArray("results");
    for (VulnerabilityScannerService.ScanResult sr : results) {
      ObjectNode item = resultsArr.addObject();
      item.put("package", sr.pkg().name());
      item.put("version", sr.pkg().version());
      item.put("ecosystem", sr.pkg().ecosystem());
      item.put("vulnerable", sr.vulnerable());
      DependencyProvenance provenance = DependencyProvenance.of(sr.pkg().dependencyChains());
      if (provenance.known()) {
        item.put("provenance", provenance.shortLabel());
        if (!provenance.transitiveRoots().isEmpty()) {
          ArrayNode roots = item.putArray("transitiveRoots");
          provenance.transitiveRoots().forEach(roots::add);
        }
      }
      FixedVersionResolver.recommendUpgrade(
              sr.vulnerabilities(), sr.pkg().name(), sr.pkg().version())
          .ifPresent(fix -> item.put("recommendedFix", fix));
      ArrayNode vulnsArr = item.putArray("vulnerabilities");
      for (OsvVulnerability vuln : sr.vulnerabilities()) {
        ObjectNode v = vulnsArr.addObject();
        v.put("id", vuln.id());
        if (!vuln.aliases().isEmpty()) {
          ArrayNode aliases = v.putArray("aliases");
          vuln.aliases().forEach(aliases::add);
        }
        String severity = SeverityAnalyzer.getSeverity(vuln);
        v.put("severity", severity);
        Double score = SeverityAnalyzer.getBaseScore(vuln);
        if (score != null) {
          v.put("cvssScore", score);
        }
        if (vuln.summary() != null && !vuln.summary().isBlank()) {
          v.put("summary", vuln.summary());
        }
        FixedVersionResolver.Resolution resolution =
            FixedVersionResolver.resolveWithRanges(vuln, sr.pkg().name(), sr.pkg().version());
        appendAffectedBranches(v, resolution);
        if (!resolution.affectedRanges().isEmpty()) {
          ArrayNode r = v.putArray("affectedRanges");
          resolution.affectedRanges().forEach(r::add);
        }
        v.put("fixedVersion", resolution.fixedVersion());
        if (!vuln.references().isEmpty()) {
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
   * CSV with one row per (dependency, vulnerability) so each finding is independently triageable. A
   * UTF-8 BOM is prepended so Excel opens it with the right encoding, and formula-injection
   * characters are neutralized.
   */
  public static void exportCsv(
      List<VulnerabilityScannerService.ScanResult> scanResults, Path outputPath)
      throws IOException {
    StringBuilder csv = new StringBuilder();
    csv.append(
        "Package,Version,Ecosystem,Vulnerability ID,CVE Aliases,Severity,CVSS,"
            + "Affected Range,Recommended Fix,Summary,Provenance\r\n");
    for (VulnerabilityScannerService.ScanResult sr : scanResults) {
      String recommendedFix =
          sr.vulnerable()
              ? FixedVersionResolver.recommendUpgrade(
                      sr.vulnerabilities(), sr.pkg().name(), sr.pkg().version())
                  .orElse("")
              : "";
      String provenance = provenanceValue(sr.pkg().dependencyChains());
      if (!sr.vulnerable() || sr.vulnerabilities().isEmpty()) {
        csv.append(csvField(sr.pkg().name()))
            .append(',')
            .append(csvField(sr.pkg().version()))
            .append(',')
            .append(csvField(sr.pkg().ecosystem()))
            .append(',')
            .append("(none),,,,,,")
            .append(csvField(recommendedFix))
            .append(',')
            .append(csvField(provenance))
            .append(",\r\n");
        continue;
      }
      for (OsvVulnerability vuln : sr.vulnerabilities()) {
        String severity = SeverityAnalyzer.getSeverity(vuln);
        Double score = SeverityAnalyzer.getBaseScore(vuln);
        String cveAliases =
            vuln.aliases() == null
                ? ""
                : vuln.aliases().stream()
                    .filter(OsvVulnerability::isCveAlias)
                    .collect(Collectors.joining(" "));
        FixedVersionResolver.Resolution resolution =
            FixedVersionResolver.resolveWithRanges(vuln, sr.pkg().name(), sr.pkg().version());
        String ranges = branchCells(resolution, sr.pkg().version());
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
            .append(score == null ? "" : SeverityAnalyzer.formatScore(score))
            .append(',')
            .append(csvField(ranges))
            .append(',')
            .append(csvField(recommendedFix))
            .append(',')
            .append(csvField(vuln.summary() == null ? "" : vuln.summary()))
            .append(',')
            .append(csvField(provenance))
            .append("\r\n");
      }
    }
    // Prepend a UTF-8 BOM so spreadsheet apps decode it correctly.
    Files.writeString(outputPath, "\uFEFF" + csv, StandardCharsets.UTF_8);
  }

  /**
   * Quotes a CSV field and neutralizes spreadsheet formula injection (fields starting with =, +, -
   * or @ are prefixed with a single quote).
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
    invocations.put("endTimeUtc", VulnerabilityReportBuilder.nowTimestamp());

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
          rule.put("helpUri", ProjectConstants.OSV_WEB_VULN_URL + ruleId);
        }

        ObjectNode result = results.addObject();
        result.put("ruleId", ruleId);
        ObjectNode message = result.putObject("message");
        message.put(
            "text",
            vuln.summary() != null
                ? sr.pkg().name() + ": " + vuln.summary()
                : sr.pkg().name() + " has vulnerability " + ruleId);
        result.put("level", sarifLevel(SeverityAnalyzer.getSeverity(vuln)));

        ObjectNode location = result.putArray("locations").addObject();
        ObjectNode physicalLocation = location.putObject("physicalLocation");
        ObjectNode artifactLocation = physicalLocation.putObject("artifactLocation");
        artifactLocation.put("uri", Ecosystem.manifestFile(sr.pkg().ecosystem()));
        artifactLocation.put("uriBaseId", "SRCROOT");
        ObjectNode region = physicalLocation.putObject("region");
        region.put("startLine", 1);

        ObjectNode properties = result.putObject("properties");
        properties.put("package", sr.pkg().name());
        properties.put("installedVersion", sr.pkg().version());
        properties.put("ecosystem", sr.pkg().ecosystem());
        DependencyProvenance provenance = DependencyProvenance.of(sr.pkg().dependencyChains());
        if (provenance.known()) {
          properties.put("provenance", provenance.shortLabel());
          if (!provenance.transitiveRoots().isEmpty()) {
            ArrayNode roots = properties.putArray("transitiveRoots");
            provenance.transitiveRoots().forEach(roots::add);
          }
        }
        FixedVersionResolver.recommendUpgrade(List.of(vuln), sr.pkg().name(), sr.pkg().version())
            .ifPresent(fix -> properties.put("recommendedFix", fix));
        FixedVersionResolver.Resolution resolution =
            FixedVersionResolver.resolveWithRanges(vuln, sr.pkg().name(), sr.pkg().version());
        if (!resolution.branches().isEmpty()) {
          appendAffectedBranches(properties, resolution);
          properties.put(
              "affectedRange",
              resolution.branches().stream()
                  .map(ReportExportService::branchText)
                  .collect(Collectors.joining(", ")));
        }
        if (!vuln.aliases().isEmpty()) {
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
    VulnerabilityScannerService.ScanSummary rollUp =
        VulnerabilityScannerService.ScanSummary.of(results);

    StringBuilder md = new StringBuilder();
    md.append("# VulnSpotter Vulnerability Report\n\n");
    md.append("- **Project:** ").append(projectName == null ? "" : projectName).append('\n');
    md.append("- **Generated:** ").append(VulnerabilityReportBuilder.nowTimestamp()).append('\n');
    md.append("- **Tool:** VulnSpotter v").append(TOOL_VERSION).append(" (OSV.dev)\n");
    md.append("- **Dependencies scanned:** ").append(rollUp.scanned()).append('\n');
    md.append("- **Vulnerable dependencies:** ").append(rollUp.vulnerable()).append('\n');
    md.append("- **Vulnerabilities found:** ").append(rollUp.totalVulnerabilities()).append("\n\n");

    if (rollUp.vulnerable() == 0) {
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
      DependencyProvenance provenance = DependencyProvenance.of(sr.pkg().dependencyChains());
      if (provenance.known()) {
        md.append("Dependency provenance: ").append(provenance.label()).append('\n');
      }
      md.append("Recommended fix: **").append(fix).append("**\n\n");
      for (OsvVulnerability vuln : sr.vulnerabilities()) {
        String severity = SeverityAnalyzer.getSeverity(vuln);
        Double score = SeverityAnalyzer.getBaseScore(vuln);
        md.append("- **[")
            .append(vuln.id())
            .append("](")
            .append(ProjectConstants.OSV_WEB_VULN_URL)
            .append(vuln.id())
            .append(")** — ")
            .append(severity);
        if (score != null) {
          md.append(" (CVSS ").append(SeverityAnalyzer.formatScore(score)).append(")");
        }
        FixedVersionResolver.Resolution resolution =
            FixedVersionResolver.resolveWithRanges(vuln, sr.pkg().name(), sr.pkg().version());
        if (!resolution.branches().isEmpty()) {
          md.append('\n');
          for (FixedVersionResolver.AffectedWindow branch : resolution.branches()) {
            md.append("  - ").append(branchText(branch));
            if (branch.containsInstalledVersion()) {
              md.append(" ← installed (").append(sr.pkg().version()).append(')');
            }
            md.append('\n');
          }
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
    return switch (SeverityAnalyzer.severityToEscalation(severity)) {
      case 0 -> "error";
      case 1 -> "warning";
      case 2 -> "note";
      default -> "warning";
    };
  }

  /**
   * Labeled branch text, e.g. {@code "Branch 3.0.x: >=3.0.0, <3.1.7 (fix: 3.1.7)"}; branches
   * without a published fix are marked instead of listing a version to upgrade to.
   */
  private static String branchText(FixedVersionResolver.AffectedWindow branch) {
    StringBuilder text = new StringBuilder();
    if (branch.branchLabel() != null) {
      text.append(branch.branchLabel()).append(": ");
    }
    text.append(branch.rangeText());
    if (branch.fixedVersion() != null) {
      text.append(" (fix: ").append(branch.fixedVersion()).append(')');
    } else {
      text.append(" (no published fix)");
    }
    return text.toString();
  }

  /** CSV cell with one entry per branch; the installed version's branch carries its marker. */
  private static String branchCells(
      FixedVersionResolver.Resolution resolution, String installedVersion) {
    return resolution.branches().stream()
        .map(
            branch -> {
              String cell = branchText(branch);
              if (branch.containsInstalledVersion()) {
                cell = cell + " (install: " + installedVersion + ")";
              }
              return cell;
            })
        .collect(Collectors.joining("; "));
  }

  /** Structured {@code affectedBranches} array for JSON/SARIF consumers. */
  private static void appendAffectedBranches(
      ObjectNode node, FixedVersionResolver.Resolution resolution) {
    ArrayNode branches = node.putArray("affectedBranches");
    for (FixedVersionResolver.AffectedWindow branch : resolution.branches()) {
      ObjectNode item = branches.addObject();
      if (branch.branchLabel() != null) {
        item.put("branch", branch.branchLabel());
      }
      item.put("range", branch.rangeText());
      if (branch.fixedVersion() != null) {
        item.put("fixedVersion", branch.fixedVersion());
      }
      if (branch.containsInstalledVersion()) {
        item.put("containsInstalledVersion", true);
      }
    }
  }

  /** Provenance for export columns; empty when the scan has no chain data for the package. */
  private static String provenanceValue(Set<List<String>> chains) {
    DependencyProvenance provenance = DependencyProvenance.of(chains);
    return provenance.known() ? provenance.shortLabel() : "";
  }
}
