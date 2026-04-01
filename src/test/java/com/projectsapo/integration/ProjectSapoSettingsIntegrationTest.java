/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.intellij.openapi.project.Project;
import com.intellij.testFramework.LightPlatformTestCase;
import com.projectsapo.settings.ProjectSapoSettings;
import org.junit.Test;

public class ProjectSapoSettingsIntegrationTest extends LightPlatformTestCase {

  @Override
  protected void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testSettingsPersistence() {
    Project project = getProject();
    ProjectSapoSettings settings = ProjectSapoSettings.getInstance(project);

    // Set some settings
    settings.setEnabled(true);
    settings.setAutoScan(true);

    // Get a new instance and check
    ProjectSapoSettings newSettings = ProjectSapoSettings.getInstance(project);
    assertThat(newSettings.isEnabled()).isTrue();
    assertThat(newSettings.isAutoScan()).isTrue();
  }
}
