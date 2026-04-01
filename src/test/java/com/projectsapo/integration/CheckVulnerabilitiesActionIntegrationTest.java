/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.actionSystem.DataContext;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.testFramework.LightPlatformTestCase;
import com.projectsapo.action.CheckVulnerabilitiesAction;
import org.junit.Test;

public class CheckVulnerabilitiesActionIntegrationTest extends LightPlatformTestCase {

  @Override
  protected void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testActionTriggersScan() throws Exception {
    Project project = getProject();

    // Create a build.gradle with vulnerable dependency
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
            implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
        }
        """;
    buildGradle.setBinaryContent(content.getBytes());

    // Create action event
    DataContext dataContext = dataId -> {
      if (CommonDataKeys.PROJECT.is(dataId)) {
        return project;
      }
      return null;
    };
    AnActionEvent event = new AnActionEvent(null, dataContext, "test", null, null, 0);

    // Perform action
    CheckVulnerabilitiesAction action = new CheckVulnerabilitiesAction();
    action.actionPerformed(event);

    // Wait for async operation
    Thread.sleep(5000); // Wait for scan to complete

    // Check that scan results are set
    assertThat(com.projectsapo.service.VulnerabilityScannerService.getInstance(project).getLastResults()).isNotEmpty();
  }
}
