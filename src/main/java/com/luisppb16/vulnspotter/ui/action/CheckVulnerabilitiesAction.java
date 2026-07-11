/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.action;

import com.intellij.notification.Notification;
import com.intellij.notification.NotificationType;
import com.intellij.notification.Notifications;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.ui.content.Content;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.ui.toolwindow.VulnSpotterToolWindow;
import com.luisppb16.vulnspotter.ui.toolwindow.VulnSpotterToolWindowFactory;
import java.util.List;
import org.jetbrains.annotations.NotNull;

/** Action to trigger vulnerability checks. */
public class CheckVulnerabilitiesAction extends AnAction {

  private static final String TITLE = "VulnSpotter";
  private static final String NOTIFICATION_GROUP_ID = "VulnSpotter Notifications";

  @Override
  public void actionPerformed(@NotNull AnActionEvent e) {
    Project project = e.getProject();
    if (project == null) return;

    // Activate the ToolWindow and trigger scan
    ToolWindow toolWindow = ToolWindowManager.getInstance(project).getToolWindow(TITLE);
    if (toolWindow != null) {
      toolWindow.show(
          () -> {
            Content content = toolWindow.getContentManager().getContent(0);
            if (content != null) {
              VulnSpotterToolWindow vulnSpotterToolWindow =
                  content.getUserData(VulnSpotterToolWindowFactory.TOOL_WINDOW_KEY);
              if (vulnSpotterToolWindow != null) {
                vulnSpotterToolWindow.runScan();
              }
            }
          });
      return;
    }

    ProgressManager.getInstance()
        .run(
            new Task.Backgroundable(project, "Checking vulnerabilities", true) {
              @Override
              public void run(@NotNull ProgressIndicator indicator) {
                indicator.setIndeterminate(true);

                try {
                  List<VulnerabilityScannerService.ScanResult> results =
                      VulnerabilityScannerService.getInstance(project).scanDependencies().join();

                  long vulnerableCount =
                      results.stream()
                          .filter(VulnerabilityScannerService.ScanResult::vulnerable)
                          .count();

                  if (vulnerableCount > 0) {
                    showNotification(
                        project,
                        "Scan complete. Found vulnerabilities in "
                            + vulnerableCount
                            + " dependencies. Check the VulnSpotter tool window for details.",
                        NotificationType.WARNING);
                  } else {
                    showNotification(
                        project,
                        "Scan complete. No vulnerabilities found.",
                        NotificationType.INFORMATION);
                  }
                } catch (Exception ex) {
                  showNotification(
                      project, "Scan failed: " + ex.getMessage(), NotificationType.ERROR);
                }
              }
            });
  }

  private void showNotification(Project project, String content, NotificationType type) {
    ApplicationManager.getApplication()
        .invokeLater(
            () -> {
              Notification notification =
                  new Notification(NOTIFICATION_GROUP_ID, TITLE, content, type);
              Notifications.Bus.notify(notification, project);
            });
  }
}
