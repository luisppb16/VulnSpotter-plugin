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
import com.intellij.openapi.util.Condition;
import com.intellij.util.messages.MessageBus;
import com.intellij.util.messages.MessageBusConnection;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.ui.notification.VulnSpotterNotifications;
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
  @Mock private Condition<?> disposedCondition;

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

    // Mock invokeLater to run immediately (both overloads: the scan callbacks use the 2-arg one)
    doAnswer(
            invocation -> {
              Runnable r = invocation.getArgument(0);
              r.run();
              return null;
            })
        .when(application)
        .invokeLater(any(Runnable.class));
    doAnswer(
            invocation -> {
              Runnable r = invocation.getArgument(0);
              r.run();
              return null;
            })
        .when(application)
        .invokeLater(any(Runnable.class), any(Condition.class));
    doReturn(disposedCondition).when(project).getDisposed();

    vulnSpotterToolWindow = new VulnSpotterToolWindow(project);
  }

  @AfterEach
  void tearDown() {
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

    when(scannerService.scanDependencies(true))
        .thenReturn(CompletableFuture.completedFuture(List.of(result)));

    // Act
    // Trigger the scan button action (simulated)
    JButton scanButton = findScanButton(vulnSpotterToolWindow.getContent());
    assertNotNull(scanButton);
    scanButton.doClick();

    // Assert
    verify(scannerService).scanDependencies(true);
  }

  @Test
  void runScan_ignoresResultsOfSupersededScan() {
    // Arrange: launch two overlapping scans; the first is still in flight when the second starts.
    OsvPackage stalePkg = new OsvPackage("stale:pkg", "Maven", "0.1.0");
    OsvPackage currentPkg = new OsvPackage("current:pkg", "Maven", "1.0.0");
    VulnerabilityScannerService.ScanResult staleScan =
        new VulnerabilityScannerService.ScanResult(stalePkg, true, List.of());
    VulnerabilityScannerService.ScanResult currentScan =
        new VulnerabilityScannerService.ScanResult(currentPkg, false, List.of());

    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> stale = new CompletableFuture<>();
    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> current =
        new CompletableFuture<>();
    when(scannerService.scanDependencies(true)).thenReturn(stale).thenReturn(current);

    // Act
    vulnSpotterToolWindow.runScan();
    vulnSpotterToolWindow.runScan();
    JButton scanButton = findScanButton(vulnSpotterToolWindow.getContent());
    stale.complete(List.of(staleScan)); // the superseded scan finishes late

    // Assert: its results never reach the table nor the annotator's data.
    verify(scannerService, never()).updateResults(anyList());
    assertNotNull(scanButton);
    assertFalse(scanButton.isEnabled());

    // Act: the current scan finishes.
    current.complete(List.of(currentScan));

    // Assert: only the current scan's results are applied and the UI is freed.
    verify(scannerService).updateResults(anyList());
    assertTrue(scanButton.isEnabled());
  }

  @Test
  void runScan_ignoresFailureOfSupersededScan() {
    // Arrange
    try (MockedStatic<VulnSpotterNotifications> notificationsMock =
        mockStatic(VulnSpotterNotifications.class)) {
      CompletableFuture<List<VulnerabilityScannerService.ScanResult>> stale =
          new CompletableFuture<>();
      CompletableFuture<List<VulnerabilityScannerService.ScanResult>> current =
          new CompletableFuture<>();
      when(scannerService.scanDependencies(true)).thenReturn(stale).thenReturn(current);

      vulnSpotterToolWindow.runScan();
      vulnSpotterToolWindow.runScan();
      JButton scanButton = findScanButton(vulnSpotterToolWindow.getContent());

      // Act: the superseded scan fails late.
      stale.completeExceptionally(new RuntimeException("OSV exploded"));

      // Assert: a superseded failure must not reset the UI or notify.
      notificationsMock.verify(
          () ->
              VulnSpotterNotifications.notifyError(any(), anyString(), anyString()),
          never());
      assertNotNull(scanButton);
      assertFalse(scanButton.isEnabled());

      // Act: the current scan finishes cleanly.
      OsvPackage pkg = new OsvPackage("current:pkg", "Maven", "1.0.0");
      VulnerabilityScannerService.ScanResult result =
          new VulnerabilityScannerService.ScanResult(pkg, false, List.of());
      current.complete(List.of(result));

      // Assert
      assertTrue(scanButton.isEnabled());
    }
  }

  private JButton findScanButton(JComponent component) {
    for (Component c : component.getComponents()) {
      if (c instanceof JButton b && "Scan Dependencies".equals(b.getText())) {
        return b;
      }
      if (c instanceof JComponent jc) {
        JButton btn = findScanButton(jc);
        if (btn != null) return btn;
      }
    }
    return null;
  }
}
