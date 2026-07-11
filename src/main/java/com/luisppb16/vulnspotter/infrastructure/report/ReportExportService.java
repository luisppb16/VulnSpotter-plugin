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
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Exports vulnerability reports into HTML and PDF files, and now JSON/SARIF. */
public final class ReportExportService {

  private static final ObjectMapper MAPPER = new ObjectMapper();

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

  public static void exportJson(Object scanResults, Path outputPath) throws IOException {
    String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(scanResults);
    Files.writeString(outputPath, json, StandardCharsets.UTF_8);
  }

  public static void exportCsv(
      List<VulnerabilityScannerService.ScanResult> scanResults, Path outputPath)
      throws IOException {
    StringBuilder csv = new StringBuilder();
    csv.append("Package,Version,Vulnerable,Vulnerabilities Count,Ecosystem\n");
    for (VulnerabilityScannerService.ScanResult result : scanResults) {
      csv.append(
          String.format(
              "\"%s\",\"%s\",%b,%d,\"%s\"\n",
              result.pkg().name().replace("\"", "\"\""),
              result.pkg().version().replace("\"", "\"\""),
              result.vulnerable(),
              result.vulnerabilities().size(),
              result.pkg().ecosystem().replace("\"", "\"\"")));
    }
    Files.writeString(outputPath, csv.toString(), StandardCharsets.UTF_8);
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
    ObjectNode tool = run.putObject("tool");
    ObjectNode driver = tool.putObject("driver");
    driver.put("name", "VulnSpotter");
    driver.put("version", "1.0.0");

    ArrayNode results = run.putArray("results");
    for (VulnerabilityScannerService.ScanResult sr : scanResults) {
      if (!sr.vulnerable()) continue;
      for (OsvVulnerability vuln : sr.vulnerabilities()) {
        ObjectNode result = results.addObject();
        result.put("ruleId", vuln.id() != null ? vuln.id() : "unknown");
        ObjectNode message = result.putObject("message");
        message.put(
            "text",
            vuln.summary() != null
                ? sr.pkg().name() + ": " + vuln.summary()
                : sr.pkg().name() + " has vulnerability " + vuln.id());
        result.put("level", "warning");

        ObjectNode location = result.putArray("locations").addObject();
        ObjectNode physicalLocation = location.putObject("physicalLocation");
        ObjectNode artifact = physicalLocation.putObject("artifact");
        artifact.put("uri", "dependency:" + sr.pkg().ecosystem() + "/" + sr.pkg().name());
        ObjectNode region = physicalLocation.putObject("region");
        region.put("startLine", 1);
      }
    }

    exportJson(sarif, outputPath);
  }
}
