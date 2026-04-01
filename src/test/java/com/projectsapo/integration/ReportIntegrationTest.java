/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.intellij.openapi.project.Project;
import com.intellij.testFramework.LightPlatformTestCase;
import com.projectsapo.model.OsvPackage;
import com.projectsapo.model.OsvVulnerability;
import com.projectsapo.report.VulnerabilityReportBuilder;
import com.projectsapo.service.VulnerabilityScannerService;
import java.util.List;
import org.junit.Test;

public class ReportIntegrationTest extends LightPlatformTestCase {

  @Override
  protected void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testReportGeneration() {
    Project project = getProject();

    // Create some scan results
    OsvPackage pkg = new OsvPackage("test", "Maven", "1.0.0");
    OsvVulnerability vuln = new OsvVulnerability("CVE-2023-1234", "Test vulnerability", null, null, null, null, null);
    VulnerabilityScannerService.ScanResult result = new VulnerabilityScannerService.ScanResult(pkg, true, List.of(vuln));

    // Generate report
    String report = VulnerabilityReportBuilder.buildHtmlReport(List.of(result), project);

    // Assert report contains expected content
    assertThat(report).isNotEmpty();
    assertThat(report).contains("CVE-2023-1234");
    assertThat(report).contains("Test vulnerability");
  }
}
