/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.vulnspotter.ui;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import com.intellij.openapi.application.Application;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import com.intellij.ui.content.ContentManager;
import com.intellij.ui.jcef.JBCefBrowser;
import com.vulnspotter.service.VulnerabilityScannerService;
import javax.swing.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SapoToolWindowFactoryTest {

  @Mock private Project project;
  @Mock private ToolWindow toolWindow;
  @Mock private ContentManager contentManager;
  @Mock private ContentFactory contentFactory;
  @Mock private Content content;
  @Mock private VulnerabilityScannerService scannerService;
  @Mock private Application application;
  @Mock private ModalityState modalityState;

  private MockedStatic<ContentFactory> contentFactoryMock;
  private MockedStatic<VulnerabilityScannerService> scannerServiceMock;
  private MockedStatic<ApplicationManager> applicationManagerMock;
  private MockedStatic<ModalityState> modalityStateMock;
  private MockedConstruction<JBCefBrowser> jbCefBrowserMockedConstruction;

  @BeforeEach
  void setUp() {
    contentFactoryMock = mockStatic(ContentFactory.class);
    scannerServiceMock = mockStatic(VulnerabilityScannerService.class);
    applicationManagerMock = mockStatic(ApplicationManager.class);
    modalityStateMock = mockStatic(ModalityState.class);

    contentFactoryMock.when(ContentFactory::getInstance).thenReturn(contentFactory);
    when(contentFactory.createContent(any(JComponent.class), anyString(), anyBoolean()))
        .thenReturn(content);
    when(toolWindow.getContentManager()).thenReturn(contentManager);

    scannerServiceMock
        .when(() -> VulnerabilityScannerService.getInstance(project))
        .thenReturn(scannerService);
    applicationManagerMock.when(ApplicationManager::getApplication).thenReturn(application);
    modalityStateMock.when(ModalityState::defaultModalityState).thenReturn(modalityState);

    // Mock JBCefBrowser construction to avoid native library loading issues in tests
    jbCefBrowserMockedConstruction =
        mockConstruction(
            JBCefBrowser.class,
            (mock, context) -> {
              when(mock.getComponent()).thenReturn(new JPanel());
            });
  }

  @AfterEach
  void tearDown() {
    contentFactoryMock.close();
    scannerServiceMock.close();
    applicationManagerMock.close();
    modalityStateMock.close();
    jbCefBrowserMockedConstruction.close();
  }

  @Test
  void testCreateToolWindowContent() {
    SapoToolWindowFactory factory = new SapoToolWindowFactory();
    factory.createToolWindowContent(project, toolWindow);

    verify(contentFactory).createContent(any(JComponent.class), eq(""), eq(false));
    verify(contentManager).addContent(content);
  }
}
