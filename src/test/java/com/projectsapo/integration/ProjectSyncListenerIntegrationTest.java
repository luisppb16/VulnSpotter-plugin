/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskId;
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskType;
import com.intellij.openapi.project.Project;
import com.intellij.testFramework.LightPlatformTestCase;
import com.projectsapo.sync.ProjectSyncListener;
import org.junit.Test;

public class ProjectSyncListenerIntegrationTest extends LightPlatformTestCase {

  @Override
  protected void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testOnSuccessTriggersScan() throws Exception {
    Project project = getProject();

    // Create a mock task id for resolve project
    ExternalSystemTaskId taskId = ExternalSystemTaskId.create("gradle", ExternalSystemTaskType.RESOLVE_PROJECT, project);
    taskId.findProject(); // Set the project

    // Create listener
    ProjectSyncListener listener = new ProjectSyncListener();

    // Call onSuccess
    listener.onSuccess(taskId);

    // Wait for async
    Thread.sleep(2000);

    // Check that scan was triggered (lastResults should be set)
    assertThat(com.projectsapo.service.VulnerabilityScannerService.getInstance(project).getLastResults()).isNotNull();
  }
}
