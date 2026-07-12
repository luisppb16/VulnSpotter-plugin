/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.toolwindow;

import com.intellij.openapi.project.DumbAware;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Key;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import org.jetbrains.annotations.NotNull;

public class VulnSpotterToolWindowFactory implements ToolWindowFactory, DumbAware {

  public static final Key<VulnSpotterToolWindow> TOOL_WINDOW_KEY =
      Key.create("com.luisppb16.vulnspotter.ui.toolwindow.VulnSpotterToolWindow");

  @Override
  public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
    VulnSpotterToolWindow vulnSpotterToolWindow = new VulnSpotterToolWindow(project);
    ContentFactory contentFactory = ContentFactory.getInstance();
    Content content = contentFactory.createContent(vulnSpotterToolWindow.getContent(), "", false);
    content.putUserData(TOOL_WINDOW_KEY, vulnSpotterToolWindow);
    // Dispose the tool window (JCEF browser, message-bus connections) with its content
    content.setDisposer(vulnSpotterToolWindow);
    toolWindow.getContentManager().addContent(content);
  }
}
