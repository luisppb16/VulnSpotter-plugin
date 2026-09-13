/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.notification;

import com.intellij.notification.NotificationGroup;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.project.Project;

/**
 * Central access point for VulnSpotter IDE notifications. Every balloon shown by the plugin goes
 * through the {@code "VulnSpotter Notifications"} group declared in {@code plugin.xml}, so the group
 * id lives in exactly one place.
 */
public final class VulnSpotterNotifications {

  public static final String GROUP_ID = "VulnSpotter Notifications";

  private VulnSpotterNotifications() {
    throw new UnsupportedOperationException("Utility class");
  }

  /** Shows an informational balloon to the user. Silently ignores a null project. */
  public static void notifyInfo(Project project, String title, String content) {
    notify(project, title, content, NotificationType.INFORMATION);
  }

  /** Shows a warning balloon to the user. Silently ignores a null project. */
  public static void notifyWarning(Project project, String title, String content) {
    notify(project, title, content, NotificationType.WARNING);
  }

  /** Shows an error balloon to the user. Silently ignores a null project. */
  public static void notifyError(Project project, String title, String content) {
    notify(project, title, content, NotificationType.ERROR);
  }

  /**
   * Shows a balloon of the given type. Fail-fast: a missing notification group registration is a
   * deployment error and is surfaced immediately instead of being silently dropped.
   */
  private static void notify(Project project, String title, String content, NotificationType type) {
    if (project == null) {
      return;
    }
    NotificationGroup group = NotificationGroupManager.getInstance().getNotificationGroup(GROUP_ID);
    if (group == null) {
      throw new IllegalStateException(
          "Notification group \"" + GROUP_ID + "\" is not registered in plugin.xml");
    }
    group.createNotification(title, content, type).notify(project);
  }
}