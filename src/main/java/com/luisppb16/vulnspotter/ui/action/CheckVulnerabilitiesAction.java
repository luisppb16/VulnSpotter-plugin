/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.action;

import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.ActionUpdateThread;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentManager;
import com.luisppb16.vulnspotter.ui.toolwindow.VulnSpotterToolWindow;
import com.luisppb16.vulnspotter.ui.toolwindow.VulnSpotterToolWindowFactory;
import org.jetbrains.annotations.NotNull;

/** Action to trigger vulnerability checks through the VulnSpotter tool window. */
public class CheckVulnerabilitiesAction extends AnAction {

  private static final String TOOL_WINDOW_ID = "VulnSpotter";
  private static final String NOTIFICATION_GROUP_ID = "VulnSpotter Notifications";

  @Override
  public @NotNull ActionUpdateThread getActionUpdateThread() {
    return ActionUpdateThread.BGT;
  }

  @Override
  public void update(@NotNull AnActionEvent e) {
    e.getPresentation().setEnabledAndVisible(e.getProject() != null);
  }

  @Override
  public void actionPerformed(@NotNull AnActionEvent e) {
    Project project = e.getProject();
    if (project == null) return;

    ToolWindow toolWindow = ToolWindowManager.getInstance(project).getToolWindow(TOOL_WINDOW_ID);
    if (toolWindow == null) {
      NotificationGroupManager.getInstance()
          .getNotificationGroup(NOTIFICATION_GROUP_ID)
          .createNotification(
              "VulnSpotter",
              "The VulnSpotter tool window is not available.",
              NotificationType.ERROR)
          .notify(project);
      return;
    }

    toolWindow.show(
        () -> {
          ContentManager cm = toolWindow.getContentManager();
          // The tool window may expose several contents; find the one carrying our panel rather than
          // assuming it lives at index 0.
          VulnSpotterToolWindow panel = null;
          for (Content content : cm.getContents()) {
            VulnSpotterToolWindow candidate =
                content.getUserData(VulnSpotterToolWindowFactory.TOOL_WINDOW_KEY);
            if (candidate != null) {
              panel = candidate;
              break;
            }
          }
          if (panel == null) {
            NotificationGroupManager.getInstance()
                .getNotificationGroup(NOTIFICATION_GROUP_ID)
                .createNotification(
                    "VulnSpotter",
                    "The VulnSpotter panel is not initialized yet. Try again in a moment.",
                    NotificationType.WARNING)
                .notify(project);
            return;
          }
          panel.runScan();
        });
  }
}
