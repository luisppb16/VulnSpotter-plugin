/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.sync;

import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskId;
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskNotificationListener;
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskType;
import com.intellij.openapi.project.Project;
import com.projectsapo.service.VulnerabilityScannerService;
import com.projectsapo.settings.ProjectSapoSettings;

public class ProjectSyncListener implements ExternalSystemTaskNotificationListener {
  @Override
  @SuppressWarnings("deprecation")
  public void onSuccess(ExternalSystemTaskId id) {
    if (id.getType() == ExternalSystemTaskType.RESOLVE_PROJECT) {
      Project project = id.findProject();
      if (project != null) {
        if (!ProjectSapoSettings.getInstance().isAutoScanOnSync()) {
          return;
        }
        VulnerabilityScannerService scanner = project.getService(VulnerabilityScannerService.class);
        if (scanner != null) {
          scanner.scanDependencies();
        }
      }
    }
  }
}
