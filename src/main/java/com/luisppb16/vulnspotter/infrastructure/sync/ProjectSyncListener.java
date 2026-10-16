/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.sync;

import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskId;
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskNotificationListener;
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskType;
import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import org.jetbrains.annotations.NotNull;

/** Triggers an automatic scan after a successful Gradle/External System project sync. */
public class ProjectSyncListener implements ExternalSystemTaskNotificationListener {

  @Override
  public void onSuccess(@NotNull String projectPath, @NotNull ExternalSystemTaskId id) {
    if (id.getType() != ExternalSystemTaskType.RESOLVE_PROJECT) {
      return;
    }
    Project project = id.findProject();
    if (project == null) {
      return;
    }
    // Same as MavenSyncListener: after a successful re-resolve every cached OSV answer may be
    // stale, so it is dropped whether or not an auto-scan follows.
    VulnerabilityScannerService scanner = VulnerabilityScannerService.getInstance(project);
    if (scanner != null) {
      scanner.invalidateCache();
    }
    if (!VulnSpotterSettings.getInstance().isAutoScanOnSync()) {
      return;
    }
    AutoScanRunner.run(project);
  }
}
