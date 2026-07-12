/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.toolwindow;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.Application;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.Project;
import com.intellij.ui.jcef.JBCefApp;
import com.intellij.util.messages.MessageBus;
import com.intellij.util.messages.MessageBusConnection;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import java.awt.Component;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import javax.swing.*;
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
class VulnSpotterToolWindowTest {

  @Mock private Project project;
  @Mock private VulnerabilityScannerService scannerService;
  @Mock private Application application;
  @Mock private ModalityState modalityState;
  @Mock private MessageBus messageBus;
  @Mock private MessageBusConnection messageBusConnection;

  private MockedStatic<VulnerabilityScannerService> scannerServiceMock;
  private MockedStatic<ApplicationManager> applicationManagerMock;
  private MockedStatic<ModalityState> modalityStateMock;

  private VulnSpotterToolWindow vulnSpotterToolWindow;

  @BeforeEach
  void setUp() {
    scannerServiceMock = mockStatic(VulnerabilityScannerService.class);
    applicationManagerMock = mockStatic(ApplicationManager.class);
    modalityStateMock = mockStatic(ModalityState.class);

    scannerServiceMock
        .when(() -> VulnerabilityScannerService.getInstance(project))
        .thenReturn(scannerService);
    applicationManagerMock.when(ApplicationManager::getApplication).thenReturn(application);
    // The constructor subscribes to LafManagerListener via the application message bus; stub it so
    // the tool window can be built without a running application.
    when(application.getMessageBus()).thenReturn(messageBus);
    when(messageBus.connect(any(Disposable.class))).thenReturn(messageBusConnection);
    modalityStateMock.when(ModalityState::defaultModalityState).thenReturn(modalityState);

    // Mock invokeLater to run immediately
    doAnswer(
            invocation -> {
              Runnable r = invocation.getArgument(0);
              r.run();
              return null;
            })
        .when(application)
        .invokeLater(any(Runnable.class));

    // Force the Swing fallback so JCEF's static initializer (which needs the application registry)
    // is never loaded under the mock application.
    VulnSpotterToolWindow.jcefSupported = () -> false;

    vulnSpotterToolWindow = new VulnSpotterToolWindow(project);
  }

  @AfterEach
  void tearDown() {
    VulnSpotterToolWindow.jcefSupported = JBCefApp::isSupported;
    scannerServiceMock.close();
    applicationManagerMock.close();
    modalityStateMock.close();
  }

  @Test
  void testInitialization() {
    assertNotNull(vulnSpotterToolWindow.getContent());
  }

  @Test
  void testRunScan() {
    // Arrange
    OsvPackage pkg = new OsvPackage("test:pkg", "Maven", "1.0.0");
    VulnerabilityScannerService.ScanResult result =
        new VulnerabilityScannerService.ScanResult(pkg, false, List.of());

    when(scannerService.scanDependencies())
        .thenReturn(CompletableFuture.completedFuture(List.of(result)));

    // Act
    // Trigger the scan button action (simulated)
    JButton scanButton = findScanButton(vulnSpotterToolWindow.getContent());
    assertNotNull(scanButton);
    scanButton.doClick();

    // Assert
    verify(scannerService).scanDependencies();
  }

  private JButton findScanButton(JComponent component) {
    for (Component c : component.getComponents()) {
      if (c instanceof JButton && "Scan Dependencies".equals(((JButton) c).getText())) {
        return (JButton) c;
      }
      if (c instanceof JComponent) {
        JButton btn = findScanButton((JComponent) c);
        if (btn != null) return btn;
      }
    }
    return null;
  }
}
