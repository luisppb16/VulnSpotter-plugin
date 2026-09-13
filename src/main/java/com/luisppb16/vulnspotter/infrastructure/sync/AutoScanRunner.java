/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.sync;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.application.service.VulnerabilityAlertService;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.ui.notification.VulnSpotterNotifications;

/**
 * Shared logic for auto-scans triggered by project sync (Gradle or Maven): runs the scan, stores
 * the results (which also refreshes editor annotations) and notifies the user when vulnerabilities
 * are found.
 */
final class AutoScanRunner {

  private static final Logger LOG = Logger.getInstance(AutoScanRunner.class);

  private AutoScanRunner() {}

  static void run(Project project) {
    VulnerabilityScannerService scanner = VulnerabilityScannerService.getInstance(project);
    if (scanner == null) {
      return;
    }
    scanner
        .scanDependencies()
        .thenAccept(
            results -> {
              scanner.updateResults(results);
              long vulnerableCount =
                  results.stream()
                      .filter(VulnerabilityScannerService.ScanResult::vulnerable)
                      .count();
              if (vulnerableCount > 0 && !project.isDisposed()) {
                VulnSpotterNotifications.notifyWarning(
                    project,
                    "VulnSpotter",
                    "Auto-scan found vulnerabilities in "
                        + vulnerableCount
                        + (vulnerableCount == 1 ? " dependency." : " dependencies.")
                        + " Open the VulnSpotter tool window for details.");
                VulnerabilityAlertService alertService =
                    VulnerabilityAlertService.getInstance(project);
                if (alertService != null) {
                  alertService.onScanCompleted(
                      results, VulnerabilityAlertService.ScanTrigger.AUTO_SYNC);
                }
              }
            })
        .exceptionally(
            ex -> {
              LOG.warn("VulnSpotter auto-scan after sync failed", ex);
              return null;
            });
  }
}
