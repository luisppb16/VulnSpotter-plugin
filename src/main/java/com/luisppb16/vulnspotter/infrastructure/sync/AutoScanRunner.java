/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.sync;

import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;

/**
 * Shared logic for auto-scans triggered by project sync (Gradle or Maven): runs the scan, stores
 * the results (which also refreshes editor annotations) and notifies the user when vulnerabilities
 * are found.
 */
final class AutoScanRunner {

  private static final Logger LOG = Logger.getInstance(AutoScanRunner.class);
  private static final String NOTIFICATION_GROUP_ID = "VulnSpotter Notifications";

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
                NotificationGroupManager.getInstance()
                    .getNotificationGroup(NOTIFICATION_GROUP_ID)
                    .createNotification(
                        "VulnSpotter",
                        "Auto-scan found vulnerabilities in "
                            + vulnerableCount
                            + (vulnerableCount == 1 ? " dependency." : " dependencies.")
                            + " Open the VulnSpotter tool window for details.",
                        NotificationType.WARNING)
                    .notify(project);
              }
            })
        .exceptionally(
            ex -> {
              LOG.warn("VulnSpotter auto-scan after sync failed", ex);
              return null;
            });
  }
}
