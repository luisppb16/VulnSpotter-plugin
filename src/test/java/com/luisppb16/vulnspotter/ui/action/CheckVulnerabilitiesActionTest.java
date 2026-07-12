/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.action;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import com.intellij.notification.Notification;
import com.intellij.notification.NotificationGroup;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentManager;
import com.luisppb16.vulnspotter.ui.toolwindow.VulnSpotterToolWindow;
import com.luisppb16.vulnspotter.ui.toolwindow.VulnSpotterToolWindowFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CheckVulnerabilitiesActionTest {

  @Mock private AnActionEvent event;
  @Mock private Project project;
  @Mock private ToolWindowManager toolWindowManager;
  @Mock private ToolWindow toolWindow;
  @Mock private ContentManager contentManager;
  @Mock private Content content;
  @Mock private VulnSpotterToolWindow vulnSpotterToolWindow;
  @Mock private NotificationGroupManager notificationGroupManager;
  @Mock private NotificationGroup notificationGroup;
  @Mock private Notification notification;

  private MockedStatic<ToolWindowManager> toolWindowManagerMock;
  private MockedStatic<NotificationGroupManager> notificationGroupManagerMock;

  private CheckVulnerabilitiesAction action;

  @BeforeEach
  void setUp() {
    toolWindowManagerMock = mockStatic(ToolWindowManager.class);
    notificationGroupManagerMock = mockStatic(NotificationGroupManager.class);

    action = new CheckVulnerabilitiesAction();

    when(event.getProject()).thenReturn(project);

    toolWindowManagerMock
        .when(() -> ToolWindowManager.getInstance(project))
        .thenReturn(toolWindowManager);

    when(toolWindow.getContentManager()).thenReturn(contentManager);
    // The action iterates every content to find the one carrying our panel.
    when(contentManager.getContents()).thenReturn(new Content[] {content});
    when(content.getUserData(VulnSpotterToolWindowFactory.TOOL_WINDOW_KEY))
        .thenReturn(vulnSpotterToolWindow);

    // runScan() is invoked inside the show(Runnable) callback; run it synchronously.
    doAnswer(
            invocation -> {
              Runnable r = invocation.getArgument(0);
              if (r != null) r.run();
              return null;
            })
        .when(toolWindow)
        .show(any(Runnable.class));

    notificationGroupManagerMock
        .when(NotificationGroupManager::getInstance)
        .thenReturn(notificationGroupManager);
    when(notificationGroupManager.getNotificationGroup(anyString())).thenReturn(notificationGroup);
    when(notificationGroup.createNotification(
            anyString(), anyString(), any(NotificationType.class)))
        .thenReturn(notification);
  }

  @AfterEach
  void tearDown() {
    toolWindowManagerMock.close();
    notificationGroupManagerMock.close();
  }

  @Test
  void testActionPerformedTriggersScanWhenPanelPresent() {
    when(toolWindowManager.getToolWindow("VulnSpotter")).thenReturn(toolWindow);

    action.actionPerformed(event);

    verify(vulnSpotterToolWindow).runScan();
  }

  @Test
  void testActionPerformedWithoutToolWindowNotifiesAndDoesNotScan() {
    when(toolWindowManager.getToolWindow("VulnSpotter")).thenReturn(null);

    action.actionPerformed(event);

    verify(vulnSpotterToolWindow, never()).runScan();
    verify(notification).notify(eq(project));
  }

  @Test
  void testActionPerformedNotifiesWhenPanelNotInitialized() {
    when(toolWindowManager.getToolWindow("VulnSpotter")).thenReturn(toolWindow);
    // No content carries the panel yet.
    when(contentManager.getContents()).thenReturn(new Content[0]);

    action.actionPerformed(event);

    verify(vulnSpotterToolWindow, never()).runScan();
    verify(notification).notify(eq(project));
  }
}
