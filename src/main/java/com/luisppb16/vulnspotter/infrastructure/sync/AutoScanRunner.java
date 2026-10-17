/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.sync;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import com.luisppb16.vulnspotter.ui.notification.VulnSpotterNotifications;

/**
 * Shared logic for auto-scans triggered by build-system syncing (Gradle or Maven) and the project
 * open scan: invalidates the scan caches after a sync and runs the scan (publication and the
 * editor-highlight refresh are owned by the service), notifying the user when vulnerabilities are
 * found.
 */
final class AutoScanRunner {

  private static final Logger LOG = Logger.getInstance(AutoScanRunner.class);

  private AutoScanRunner() {}

  /**
   * Invalidates the cached batch answers after a build-system sync (hydrated records revalidate by
   * their {@code modified} stamp) and runs the auto-scan when {@code autoScanOnSync} is enabled. A
   * re-import can change any dependency's resolved version, so every cached batch answer may be
   * stale once a sync finishes — it is dropped whether or not an auto-scan follows, because a
   * manual scan right after the sync must not consume stale cache either.
   *
   * <p>Both build-system listeners share this, so the invalidation policy lives in exactly one
   * place.
   */
  static void runAfterSync(Project project) {
    VulnerabilityScannerService scanner = VulnerabilityScannerService.getInstance(project);
    if (scanner != null) {
      scanner.invalidateCache();
    }
    if (!VulnSpotterSettings.getInstance().isAutoScanOnSync()) {
      return;
    }
    run(project);
  }

  static void run(Project project) {
    VulnerabilityScannerService scanner = VulnerabilityScannerService.getInstance(project);
    if (scanner == null) {
      return;
    }
    scanAndNotify(project, scanner, true);
  }

  /**
   * Runs the auto-scan and notifies on findings. The scan coalesces into a running one and borrows
   * its lifecycle: the tool window decorates its own future with a timeout and a Cancel button, so
   * a borrowed scan can complete exceptionally without this trigger having been served. One retry
   * keeps the sync-triggered guarantee real; the retry never retries again, so a persistent failure
   * surfaces exactly two log lines instead of a loop.
   */
  private static void scanAndNotify(
      Project project, VulnerabilityScannerService scanner, boolean allowOneRetry) {
    scanner
        .scanDependencies()
        .thenAccept(
            results -> {
              // Publication (and annotation refresh) is owned by the service; a late completion
              // of a superseded scan is dropped there too. This trigger only counts and notifies.
              long vulnerableCount =
                  VulnerabilityScannerService.ScanSummary.of(results).vulnerable();
              if (vulnerableCount > 0 && !project.isDisposed()) {
                VulnSpotterNotifications.notifyWarning(
                    project,
                    VulnSpotterNotifications.TITLE,
                    "Auto-scan found vulnerabilities in "
                        + vulnerableCount
                        + (vulnerableCount == 1 ? " dependency." : " dependencies.")
                        + " Open the VulnSpotter tool window for details.");
              }
            })
        .exceptionally(
            ex -> {
              if (allowOneRetry && !project.isDisposed()) {
                LOG.warn(
                    "VulnSpotter auto-scan did not complete (borrowed scan cancelled or timed out);"
                        + " rerunning it once",
                    ex);
                scanAndNotify(project, scanner, false);
                return null;
              }
              LOG.warn("VulnSpotter auto-scan failed", ex);
              return null;
            });
  }
}
