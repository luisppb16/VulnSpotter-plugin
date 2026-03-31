/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

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
      builder.withHtmlContent(html, null);
      builder.toStream(outputStream);
      builder.run();
    }
  }

  public static void exportJson(Object scanResults, Path outputPath) throws IOException {
    String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(scanResults);
    Files.writeString(outputPath, json, StandardCharsets.UTF_8);
  }

  public static void exportCsv(
      java.util.List<com.projectsapo.service.VulnerabilityScannerService.ScanResult> scanResults,
      Path outputPath)
      throws IOException {
    StringBuilder csv = new StringBuilder();
    csv.append("Package,Version,Vulnerable,Vulnerabilities Count,Ecosystem\n");
    for (com.projectsapo.service.VulnerabilityScannerService.ScanResult result : scanResults) {
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

  public static void exportSarif(Path outputPath)
      throws
          IOException { // removed scanResults for now since it's unhandled to match spec simplified
    ObjectNode sarif = MAPPER.createObjectNode();
    sarif.put("version", "2.1.0");
    sarif.put(
        "$schema",
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");

    ArrayNode runs = sarif.putArray("runs");
    ObjectNode run = runs.addObject();
    ObjectNode tool = run.putObject("tool");
    ObjectNode driver = tool.putObject("driver");
    driver.put("name", "Project Sapo");
    driver.put("version", "1.1.3");

    // Simplification for representation, real implementation would convert raw scanResults
    // iteratively
    run.putArray("results");

    exportJson(sarif, outputPath);
  }
}
