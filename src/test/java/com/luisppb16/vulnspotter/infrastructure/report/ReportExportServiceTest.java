/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.report;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReportExportServiceTest {

  @TempDir Path tempDir;

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
}
