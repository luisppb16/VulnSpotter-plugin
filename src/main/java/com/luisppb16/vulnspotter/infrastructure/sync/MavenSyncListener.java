/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.sync;

import com.intellij.openapi.module.Module;
import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import java.util.Collection;
import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.idea.maven.project.MavenImportListener;
import org.jetbrains.idea.maven.project.MavenProject;

/**
 * Triggers an automatic scan after a Maven re-import. Gradle syncs are covered by {@link
 * ProjectSyncListener}; Maven does not go through the External System pipeline, so it needs its
 * own listener.
 */
public class MavenSyncListener implements MavenImportListener {

  private final Project project;

  public MavenSyncListener(Project project) {
    this.project = project;
  }

  @Override
  public void importFinished(
      @NotNull Collection<MavenProject> importedProjects, @NotNull List<Module> newModules) {
    if (importedProjects.isEmpty() || !VulnSpotterSettings.getInstance().isAutoScanOnSync()) {
      return;
    }
    AutoScanRunner.run(project);
  }
}
