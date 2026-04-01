/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.testFramework.LightPlatformTestCase;
import com.projectsapo.service.VulnerabilityScannerService;
import java.util.List;
import org.junit.Test;

public class SafeDependenciesIntegrationTest extends LightPlatformTestCase {

  @Override
  protected void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testScanSafeDependencies() throws Exception {
    Project project = getProject();

    // Create a build.gradle file with safe dependency
    createBuildGradleWithSafeDep();

    // Run the scan
    VulnerabilityScannerService service = VulnerabilityScannerService.getInstance(project);
    List<VulnerabilityScannerService.ScanResult> results = service.scanDependencies().get();

    // Assert that no vulnerabilities are found
    assertThat(results.stream().noneMatch(VulnerabilityScannerService.ScanResult::vulnerable)).isTrue();
  }

  private void createBuildGradleWithSafeDep() throws Exception {
    VirtualFile moduleDir = getModule().getModuleFile().getParent();
    VirtualFile buildGradle = moduleDir.createChildData(this, "build.gradle");
    String content = """
        plugins {
            id 'java'
        }

        repositories {
            mavenCentral()
        }

        dependencies {
            implementation 'org.apache.commons:commons-lang3:3.12.0' // Safe version
        }
        """;
    buildGradle.setBinaryContent(content.getBytes());
  }
}
