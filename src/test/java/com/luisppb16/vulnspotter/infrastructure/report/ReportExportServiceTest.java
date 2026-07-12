/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.report;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService.ScanResult;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReportExportServiceTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  @TempDir Path tempDir;

  /** One vulnerable Maven dependency (with a real fixed range) plus one clean dependency. */
  private static List<ScanResult> sampleResults() {
    OsvVulnerability vuln =
        new OsvVulnerability(
            "GHSA-test-1234",
            "Deserialization of untrusted data",
            "details",
            List.of("CVE-2024-0001"),
            null,
            null,
            null,
            List.of(
                new OsvVulnerability.Severity(
                    "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
            List.of(
                new OsvVulnerability.Affected(
                    new OsvVulnerability.Package(
                        "com.fasterxml.jackson.core:jackson-databind", "Maven", null),
                    List.of(
                        new OsvVulnerability.Range(
                            "ECOSYSTEM",
                            List.of(
                                new OsvVulnerability.Event("0", null),
                                new OsvVulnerability.Event(null, "2.9.10")))),
                    null,
                    Map.of())),
            Collections.emptyList(),
            Collections.emptyMap());

    ScanResult vulnerable =
        new ScanResult(
            new OsvPackage("com.fasterxml.jackson.core:jackson-databind", "Maven", "2.9.0"),
            true,
            List.of(vuln));
    ScanResult clean =
        new ScanResult(new OsvPackage("org.safe:library", "Maven", "1.0.0"), false, List.of());
    return List.of(vulnerable, clean);
  }

  @Test
  void exportsHtmlAndPdfFiles() throws Exception {
    String html = "<html><body><h1>Report</h1><p>content</p></body></html>";

    Path htmlPath = tempDir.resolve("report.html");
    Path pdfPath = tempDir.resolve("report.pdf");

    ReportExportService.exportHtml(html, htmlPath);
    ReportExportService.exportPdf(html, pdfPath);

    assertTrue(Files.exists(htmlPath));
    assertTrue(Files.size(htmlPath) > 0);
    assertTrue(Files.exists(pdfPath));
    assertTrue(Files.size(pdfPath) > 0);
  }

  @Test
  void exportsCsvWithOneRowPerVulnerabilityAndExpectedColumns() throws Exception {
    Path csvPath = tempDir.resolve("report.csv");

    ReportExportService.exportCsv(sampleResults(), csvPath);

    String content = Files.readString(csvPath);
    // UTF-8 BOM for Excel.
    assertThat(content).startsWith("\uFEFF");
    List<String> lines = content.substring(1).lines().toList();
    assertThat(lines.get(0))
        .isEqualTo(
            "Package,Version,Ecosystem,Vulnerability ID,CVE Aliases,Severity,CVSS,"
                + "Affected Range,Recommended Fix,Summary");
    // 1 header + 1 vulnerable row + 1 clean row.
    assertThat(lines).hasSize(3);
    assertThat(lines.get(1))
        .contains("\"com.fasterxml.jackson.core:jackson-databind\"")
        .contains("\"2.9.0\"")
        .contains("\"GHSA-test-1234\"")
        .contains("\"CVE-2024-0001\"")
        .contains("\"CRITICAL\"")
        .contains("9.8")
        .contains("\"2.9.10\"");
    assertThat(lines.get(2)).contains("\"org.safe:library\"").contains("(none)");
  }

  @Test
  void csvNeutralizesFormulaInjection() throws Exception {
    OsvVulnerability vuln =
        new OsvVulnerability(
            "=cmd|calc",
            "=HYPERLINK(\"http://evil\")",
            "details",
            null,
            List.of(),
            List.of(),
            Map.of());
    ScanResult result = new ScanResult(new OsvPackage("g:a", "Maven", "1.0"), true, List.of(vuln));
    Path csvPath = tempDir.resolve("inject.csv");

    ReportExportService.exportCsv(List.of(result), csvPath);

    String content = Files.readString(csvPath);
    // Fields starting with '=' must be prefixed with a quote so spreadsheets treat them as text.
    assertThat(content).contains("\"'=cmd|calc\"").contains("\"'=HYPERLINK(");
    assertThat(content).doesNotContain(",\"=cmd|calc\"");
  }

  @Test
  void exportsValidSarifWithLocationsAndRules() throws Exception {
    Path sarifPath = tempDir.resolve("report.sarif");

    ReportExportService.exportSarif(sampleResults(), sarifPath);

    JsonNode sarif = MAPPER.readTree(sarifPath.toFile());
    assertThat(sarif.get("version").asText()).isEqualTo("2.1.0");
    JsonNode run = sarif.get("runs").get(0);
    assertThat(run.get("tool").get("driver").get("name").asText()).isEqualTo("VulnSpotter");

    JsonNode rules = run.get("tool").get("driver").get("rules");
    assertThat(rules).hasSize(1);
    assertThat(rules.get(0).get("id").asText()).isEqualTo("GHSA-test-1234");
    assertThat(rules.get(0).get("helpUri").asText())
        .isEqualTo("https://osv.dev/vulnerability/GHSA-test-1234");

    // Only the vulnerable dependency produces a result; CRITICAL maps to "error".
    JsonNode results = run.get("results");
    assertThat(results).hasSize(1);
    JsonNode result = results.get(0);
    assertThat(result.get("ruleId").asText()).isEqualTo("GHSA-test-1234");
    assertThat(result.get("level").asText()).isEqualTo("error");
    assertThat(
            result
                .get("locations")
                .get(0)
                .get("physicalLocation")
                .get("artifactLocation")
                .get("uri")
                .asText())
        .isEqualTo("pom.xml");
    JsonNode properties = result.get("properties");
    assertThat(properties.get("package").asText())
        .isEqualTo("com.fasterxml.jackson.core:jackson-databind");
    assertThat(properties.get("recommendedFix").asText()).isEqualTo("2.9.10");
  }

  @Test
  void exportsJsonReportWithSummaryAndVulnerabilityDetails() throws Exception {
    Path jsonPath = tempDir.resolve("report.json");

    ReportExportService.exportJsonReport("demo-project", sampleResults(), jsonPath);

    JsonNode root = MAPPER.readTree(jsonPath.toFile());
    assertThat(root.get("project").asText()).isEqualTo("demo-project");
    assertThat(root.get("summary").get("totalDependencies").asInt()).isEqualTo(2);
    assertThat(root.get("summary").get("vulnerableDependencies").asInt()).isEqualTo(1);
    assertThat(root.get("summary").get("totalVulnerabilities").asInt()).isEqualTo(1);

    JsonNode vulnerable = root.get("results").get(0);
    assertThat(vulnerable.get("recommendedFix").asText()).isEqualTo("2.9.10");
    JsonNode vuln = vulnerable.get("vulnerabilities").get(0);
    assertThat(vuln.get("id").asText()).isEqualTo("GHSA-test-1234");
    assertThat(vuln.get("severity").asText()).isEqualTo("CRITICAL");
    assertThat(vuln.get("cvssScore").asDouble()).isEqualTo(9.8);
    assertThat(vuln.get("fixedVersion").asText()).isEqualTo("2.9.10");
  }

  @Test
  void exportsMarkdownReport() throws Exception {
    Path mdPath = tempDir.resolve("report.md");

    ReportExportService.exportMarkdown("demo-project", sampleResults(), mdPath);

    String md = Files.readString(mdPath);
    assertThat(md)
        .contains("# VulnSpotter Vulnerability Report")
        .contains("`com.fasterxml.jackson.core:jackson-databind` @ 2.9.0")
        .contains("Recommended fix: **2.9.10**")
        .contains("[GHSA-test-1234](https://osv.dev/vulnerability/GHSA-test-1234)")
        .contains("CRITICAL");
  }
}
