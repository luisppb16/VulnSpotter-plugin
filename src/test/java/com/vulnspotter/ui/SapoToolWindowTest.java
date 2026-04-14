/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.vulnspotter.ui;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.intellij.openapi.application.Application;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.Project;
import com.intellij.ui.jcef.JBCefBrowser;
import com.vulnspotter.model.OsvPackage;
import com.vulnspotter.service.VulnerabilityScannerService;
import java.awt.Component;
import java.util.List;
import java.util.concurrent.CompletableFuture;
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
class SapoToolWindowTest {

  @Mock private Project project;
  @Mock private VulnerabilityScannerService scannerService;
  @Mock private Application application;
  @Mock private ModalityState modalityState;

  private MockedStatic<VulnerabilityScannerService> scannerServiceMock;
  private MockedStatic<ApplicationManager> applicationManagerMock;
  private MockedStatic<ModalityState> modalityStateMock;
  private MockedConstruction<JBCefBrowser> jbCefBrowserMockedConstruction;

  private SapoToolWindow sapoToolWindow;

  @BeforeEach
  void setUp() {
    scannerServiceMock = mockStatic(VulnerabilityScannerService.class);
    applicationManagerMock = mockStatic(ApplicationManager.class);
    modalityStateMock = mockStatic(ModalityState.class);

    scannerServiceMock
        .when(() -> VulnerabilityScannerService.getInstance(project))
        .thenReturn(scannerService);
    applicationManagerMock.when(ApplicationManager::getApplication).thenReturn(application);
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

    // Mock JBCefBrowser construction to avoid native library loading issues in tests
    jbCefBrowserMockedConstruction =
        mockConstruction(
            JBCefBrowser.class,
            (mock, context) -> {
              when(mock.getComponent()).thenReturn(new JPanel());
            });

    sapoToolWindow = new SapoToolWindow(project);
  }

  @AfterEach
  void tearDown() {
    scannerServiceMock.close();
    applicationManagerMock.close();
    modalityStateMock.close();
    jbCefBrowserMockedConstruction.close();
  }

  @Test
  void testInitialization() {
    assertNotNull(sapoToolWindow.getContent());
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
    JButton scanButton = findScanButton(sapoToolWindow.getContent());
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
