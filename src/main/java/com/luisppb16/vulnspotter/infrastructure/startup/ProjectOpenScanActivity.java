/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.startup;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.startup.ProjectActivity;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.service.SeverityAnalyzer;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import com.luisppb16.vulnspotter.ui.notification.VulnSpotterNotifications;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Runs a vulnerability scan when a project is opened, if the {@code analyzeOnProjectOpen} setting
 * is enabled. The scan runs asynchronously: when it completes, the results are stored in the
 * scanner service and, when a critical vulnerability was found, surfaced through a warning balloon.
 *
 * <p>Every exit path is safe: a missing settings service (headless), a disabled toggle or a
 * disposed project simply skip the scan.
 */
public final class ProjectOpenScanActivity implements ProjectActivity {

  private static final Logger LOG = Logger.getInstance(ProjectOpenScanActivity.class);

  /**
   * Whether any scan result carries at least one {@link SeverityAnalyzer#CRITICAL} vulnerability. A
   * result without vulnerabilities (or without severity data) is never critical.
   *
   * @param results scan results, may be {@code null}.
   * @return {@code true} when a critical vulnerability was found.
   */
  static boolean hasCriticalResults(List<VulnerabilityScannerService.ScanResult> results) {
    SeverityAnalyzer analyzer = new SeverityAnalyzer();
    return results != null
        && results.stream()
            .anyMatch(
                result ->
                    SeverityAnalyzer.CRITICAL.equals(
                        analyzer.getHighestSeverity(result.vulnerabilities())));
  }

  @Override
  @Nullable
  public Object execute(
      @NotNull Project project, @NotNull Continuation<? super Unit> continuation) {
    VulnSpotterSettings settings = VulnSpotterSettings.getInstance();
    if (settings == null || !settings.isAnalyzeOnProjectOpen() || project.isDisposed()) {
      return Unit.INSTANCE;
    }
    VulnerabilityScannerService scanner = VulnerabilityScannerService.getInstance(project);
    if (scanner == null) {
      return Unit.INSTANCE;
    }
    scanner
        .scanDependencies()
        .thenAccept(
            results -> {
              if (project.isDisposed()) {
                return;
              }
              scanner.updateResults(results);
              if (hasCriticalResults(results)) {
                VulnSpotterNotifications.notifyWarning(
                    project,
                    "VulnSpotter",
                    "Critical CVEs found at project open. Open the VulnSpotter tool window for "
                        + "details.");
              }
            })
        .exceptionally(
            ex -> {
              LOG.warn("VulnSpotter project-open scan failed", ex);
              return null;
            });
    return Unit.INSTANCE;
  }
}
