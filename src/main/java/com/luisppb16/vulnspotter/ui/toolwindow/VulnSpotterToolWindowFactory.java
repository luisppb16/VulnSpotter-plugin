/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.toolwindow;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.DumbAware;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.CheckedDisposable;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.util.Key;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.components.JBPanel;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import org.jetbrains.annotations.NotNull;

public class VulnSpotterToolWindowFactory implements ToolWindowFactory, DumbAware {

  public static final Key<VulnSpotterToolWindow> TOOL_WINDOW_KEY =
      Key.create("com.luisppb16.vulnspotter.ui.toolwindow.VulnSpotterToolWindow");

  @Override
  public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
    // A non-null placeholder is required: the platform validates getComponent() != null when the
    // content is added. The real panel replaces it once construction completes.
    Content content = ContentFactory.getInstance().createContent(new JBPanel<>(), "", false);
    toolWindow.getContentManager().addContent(content);
    CheckedDisposable contentDisposed = Disposer.newCheckedDisposable();
    if (!Disposer.tryRegister(content, contentDisposed)) {
      return;
    }

    // Building the panel constructs a JBCefBrowser, which triggers JBCefApp's class initializer.
    // createToolWindowContent runs during early IDE startup (ToolWindowSetInitializer), so defer
    // construction until the IDE is idle. The <clinit> itself is only safe once HttpConfigurable
    // is initialized outside it: its first creation requests ProxyMigrationService, a nested
    // service lookup the platform rejects from a class initializer ("Class initialization must
    // not depend on services"). JcefDetailsPanel resolves ProxySettings for that, which creates
    // HttpConfigurable outside any class initializer.
    ApplicationManager.getApplication()
        .invokeLater(
            () -> {
              if (contentDisposed.isDisposed()) {
                return;
              }
              VulnSpotterToolWindow vulnSpotterToolWindow = new VulnSpotterToolWindow(project);
              content.setComponent(vulnSpotterToolWindow.getContent());
              content.putUserData(TOOL_WINDOW_KEY, vulnSpotterToolWindow);
              // Dispose the tool window (JCEF browser, message-bus connections) with its content
              content.setDisposer(vulnSpotterToolWindow);
            },
            ModalityState.nonModal(),
            project.getDisposed());
  }
}
