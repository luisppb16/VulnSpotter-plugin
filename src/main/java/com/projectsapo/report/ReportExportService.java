/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.report;

import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Exports vulnerability reports into HTML and PDF files. */
public final class ReportExportService {

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
}

