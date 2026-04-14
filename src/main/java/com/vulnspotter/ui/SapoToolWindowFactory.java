/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.vulnspotter.ui;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Key;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import org.jetbrains.annotations.NotNull;

public class SapoToolWindowFactory implements ToolWindowFactory {

  public static final Key<SapoToolWindow> SAPO_TOOL_WINDOW_KEY =
      Key.create("com.vulnspotter.ui.SapoToolWindow");

  @Override
  public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
    SapoToolWindow sapoToolWindow = new SapoToolWindow(project);
    ContentFactory contentFactory = ContentFactory.getInstance();
    Content content = contentFactory.createContent(sapoToolWindow.getContent(), "", false);
    content.putUserData(SAPO_TOOL_WINDOW_KEY, sapoToolWindow);
    toolWindow.getContentManager().addContent(content);
  }
}
