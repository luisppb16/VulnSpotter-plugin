/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.testFramework.LightPlatformTestCase;
import org.junit.Test;

public class SapoToolWindowIntegrationTest extends LightPlatformTestCase {

  @Override
  protected void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testToolWindowIsRegistered() {
    Project project = getProject();
    ToolWindowManager toolWindowManager = ToolWindowManager.getInstance(project);
    ToolWindow toolWindow = toolWindowManager.getToolWindow("Project Sapo");

    assertThat(toolWindow).isNotNull();
    assertThat(toolWindow.getId()).isEqualTo("Project Sapo");
  }
}
