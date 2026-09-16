/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.toolwindow;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.Application;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Condition;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import com.intellij.ui.content.ContentManager;
import com.intellij.util.messages.MessageBus;
import com.intellij.util.messages.MessageBusConnection;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import javax.swing.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class VulnSpotterToolWindowFactoryTest {

  @Mock private Project project;
  @Mock private ToolWindow toolWindow;
  @Mock private ContentManager contentManager;
  @Mock private ContentFactory contentFactory;
  @Mock private Content content;
  @Mock private VulnerabilityScannerService scannerService;
  @Mock private Application application;
  @Mock private ModalityState modalityState;
  @Mock private MessageBus messageBus;
  @Mock private MessageBusConnection messageBusConnection;

  private MockedStatic<ContentFactory> contentFactoryMock;
  private MockedStatic<VulnerabilityScannerService> scannerServiceMock;
  private MockedStatic<ApplicationManager> applicationManagerMock;
  private MockedStatic<ModalityState> modalityStateMock;

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
    // The deferred runnable subscribes to the application message bus; stub it so the factory can
    // build the panel without a running application.
    when(application.getMessageBus()).thenReturn(messageBus);
    when(messageBus.connect(any(Disposable.class))).thenReturn(messageBusConnection);
    when(project.getDisposed()).thenReturn(disposedProject -> false);
    // The panel construction touches JBScrollPane/JBScrollBar internals that query modality state;
    // stub both accessors so it can build without a running application.
    modalityStateMock.when(ModalityState::defaultModalityState).thenReturn(modalityState);
    modalityStateMock.when(ModalityState::nonModal).thenReturn(modalityState);
  }

  @AfterEach
  void tearDown() {
    contentFactoryMock.close();
    scannerServiceMock.close();
    applicationManagerMock.close();
    modalityStateMock.close();
  }

  @Test
  void testCreateToolWindowContent() {
    // Given: a factory whose panel construction is deferred until the IDE is idle
    VulnSpotterToolWindowFactory factory = new VulnSpotterToolWindowFactory();
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);

    // When: the tool window content is created during startup
    factory.createToolWindowContent(project, toolWindow);

    // Then: only the content shell with placeholder is added synchronously; the panel is built
    // later
    verify(contentFactory).createContent(any(JComponent.class), eq(""), eq(false));
    verify(contentManager).addContent(content);
    verify(application)
        .invokeLater(runnableCaptor.capture(), eq(modalityState), any(Condition.class));
    runnableCaptor.getValue().run();
    verify(content).setComponent(any(JComponent.class));
    verify(content)
        .putUserData(
            eq(VulnSpotterToolWindowFactory.TOOL_WINDOW_KEY), any(VulnSpotterToolWindow.class));
    verify(content).setDisposer(any(VulnSpotterToolWindow.class));
  }

  @Test
  void testCreateToolWindowContentDoesNotBuildWhenContentDisposed() {
    // Given: a factory whose content shell is disposed before the deferred runnable runs
    VulnSpotterToolWindowFactory factory = new VulnSpotterToolWindowFactory();
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    factory.createToolWindowContent(project, toolWindow);
    verify(application)
        .invokeLater(runnableCaptor.capture(), eq(modalityState), any(Condition.class));
    Disposer.dispose(content);

    // When: the deferred runnable finally runs
    runnableCaptor.getValue().run();

    // Then: the panel is never built nor attached to the disposed content
    verify(content, never()).setComponent(any(JComponent.class));
    verify(content, never()).setDisposer(any(VulnSpotterToolWindow.class));
  }
}
