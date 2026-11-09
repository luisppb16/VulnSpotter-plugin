/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.toolwindow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.Application;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Condition;
import com.intellij.ui.table.JBTable;
import com.intellij.util.messages.MessageBus;
import com.intellij.util.messages.MessageBusConnection;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.model.DependencyProvenance;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import com.luisppb16.vulnspotter.testsupport.VulnFixtures;
import com.luisppb16.vulnspotter.ui.notification.VulnSpotterNotifications;
import java.awt.Component;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
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
  private DetailsPanel detailsPanel;

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

    VulnSpotterSettings settings = mock(VulnSpotterSettings.class);
    lenient().when(settings.getIgnoredCves()).thenReturn(List.of());
    lenient().when(settings.getMinimumSeverity()).thenReturn("SAFE");
    lenient().when(settings.getCacheDurationMinutes()).thenReturn(60);
    when(application.getService(VulnSpotterSettings.class)).thenReturn(settings);
    detailsPanel = mock(DetailsPanel.class);
    DetailsPanelFactory panelFactory = mock(DetailsPanelFactory.class);
    when(application.getService(DetailsPanelFactory.class)).thenReturn(panelFactory);
    lenient().when(panelFactory.create()).thenReturn(detailsPanel);
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

    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> stale =
        new CompletableFuture<>();
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

    // Assert: the UI is freed only by the current scan's completion (publication of the results
    // is owned by the scanner service, so no updateResults contract is verified here).
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
          () -> VulnSpotterNotifications.notifyError(any(), anyString(), anyString()), never());
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

  private JBTable findResultsTable(JComponent component) {
    for (Component c : component.getComponents()) {
      if (c instanceof JBTable table) {
        return table;
      }
      if (c instanceof JComponent jc) {
        JBTable table = findResultsTable(jc);
        if (table != null) return table;
      }
    }
    return null;
  }

  @Test
  void detailsPanel_paintsRemediationBeforeTheDependencyTreeBeforeTheVulnCards() {
    // Given: a vulnerable transitive dependency, scanned and selected on the results table.
    OsvPackage transitive =
        new OsvPackage(
            "com.fasterxml.jackson.core:jackson-databind",
            "Maven",
            "2.9.0",
            Set.of(
                List.of(
                    "org.springframework:spring-boot-starter-web",
                    "com.fasterxml.jackson.core:jackson-databind"),
                List.of(
                    "io.projectreactor:reactor-netty",
                    "com.fasterxml.jackson.core:jackson-databind")));
    VulnerabilityScannerService.ScanResult result =
        VulnFixtures.result(
            transitive,
            true,
            VulnFixtures.vuln(
                "GHSA-test-1234",
                "DoS",
                "details",
                null,
                List.of(
                    VulnFixtures.affected("com.fasterxml.jackson.core:jackson-databind", "2.9.10")),
                List.of(),
                Map.of()));
    when(scannerService.scanDependencies(true))
        .thenReturn(CompletableFuture.completedFuture(List.of(result)));

    ArgumentCaptor<String> htmlCaptor = ArgumentCaptor.forClass(String.class);

    // When: the scan finishes and its only row gets selected.
    vulnSpotterToolWindow.runScan();
    JBTable table = findResultsTable(vulnSpotterToolWindow.getContent());
    assertNotNull(table);
    table.setRowSelectionInterval(0, 0);

    // Then: Remediation comes first, then the dependency tree, then the vulnerability cards.
    verify(detailsPanel, atLeastOnce()).loadHtml(htmlCaptor.capture());
    String html = htmlCaptor.getAllValues().getLast();
    String body = html.substring(html.lastIndexOf("</style>") + "</style>".length());
    int remediation = body.indexOf("remediation-title");
    int dependencyTree = body.indexOf("snyk-chain");
    int severity = body.indexOf("class='card");
    assertThat(remediation).isGreaterThan(0);
    assertThat(dependencyTree).isGreaterThan(remediation);
    assertThat(severity).isGreaterThan(dependencyTree);

    // And: one merged mvn dependency:tree-shaped listing, without "Path #" headers.
    assertThat(body).doesNotContain("Path #");
    assertThat(body)
        .contains("├─ <span class='icon'>📄</span> io.projectreactor:reactor-netty")
        .contains("└─ <span class='icon'>📄</span> org.springframework:spring-boot-starter-web")
        .contains("│  └─ <span class='icon'>⚠️</span> <b class='target'>")
        .contains("   └─ <span class='icon'>⚠️</span> <b class='target'>")
        .contains("<b class='target'>com.fasterxml.jackson.core:jackson-databind 2.9.0</b>");
  }

  @Test
  void detailsPanel_platformProvidedPackage_explainsInsteadOfSuggestingUpgrades() {
    // Given: a vulnerable package whose only chain the intellijPlatform toolchain injected.
    OsvPackage provided =
        VulnFixtures.pkgWithChains(
            "at.yawk.lz4:lz4-java",
            "1.11.3",
            List.of(List.of(DependencyProvenance.PLATFORM_ROOT, "at.yawk.lz4:lz4-java")));
    VulnerabilityScannerService.ScanResult result =
        VulnFixtures.result(
            provided,
            true,
            VulnFixtures.vuln(
                "GHSA-test-1234",
                "DoS",
                "details",
                null,
                List.of(VulnFixtures.affected("at.yawk.lz4:lz4-java", "1.12.0")),
                List.of(),
                Map.of()));
    when(scannerService.scanDependencies(true))
        .thenReturn(CompletableFuture.completedFuture(List.of(result)));

    ArgumentCaptor<String> htmlCaptor = ArgumentCaptor.forClass(String.class);

    // When: the scan finishes and its only row gets selected.
    vulnSpotterToolWindow.runScan();
    JBTable table = findResultsTable(vulnSpotterToolWindow.getContent());
    assertNotNull(table);
    table.setRowSelectionInterval(0, 0);

    // Then: the panel explains where the jar comes from and suggests no upgrade path.
    verify(detailsPanel, atLeastOnce()).loadHtml(htmlCaptor.capture());
    String html = htmlCaptor.getAllValues().getLast();
    String body = html.substring(html.lastIndexOf("</style>") + "</style>".length());
    assertThat(body).contains("Provided by the intellijPlatform toolchain");
    assertThat(body).contains("no source-level upgrade applies");
    assertThat(body).doesNotContain("Upgrade <b>");
    assertThat(body).doesNotContain("To fix transitively");
    assertThat(body).contains("<span class='icon'>📄</span> intellijPlatform (provided)");
  }

  @Test
  void runScan_clearsDetailsPanelDuringScanAndLeavesItEmptyAfter() {
    // Given: a finished scan on the table with its vulnerable row selected.
    OsvPackage pkg = VulnFixtures.pkg("test:pkg", "1.0.0");
    VulnerabilityScannerService.ScanResult result =
        VulnFixtures.result(pkg, true, VulnFixtures.dbSeverity("GHSA-test", "HIGH"));
    when(scannerService.scanDependencies(true))
        .thenReturn(CompletableFuture.completedFuture(List.of(result)));
    vulnSpotterToolWindow.runScan();
    JBTable table = findResultsTable(vulnSpotterToolWindow.getContent());
    assertNotNull(table);
    table.setRowSelectionInterval(0, 0);

    ArgumentCaptor<String> htmlCaptor = ArgumentCaptor.forClass(String.class);
    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> reScan =
        new CompletableFuture<>();
    when(scannerService.scanDependencies(true)).thenReturn(reScan);

    // When: a second scan launches while the row selection exists.
    vulnSpotterToolWindow.runScan();

    // Then: during the scan the preview resets to the empty state.
    verify(detailsPanel, atLeastOnce()).loadHtml(htmlCaptor.capture());
    assertThat(htmlCaptor.getAllValues().getLast()).contains("Select a dependency to see details.");

    // When: the re-scan finishes.
    reScan.complete(List.of(result));

    // Then: the selection does not come back and the preview stays empty.
    assertThat(table.getSelectedRow()).isEqualTo(-1);
    verify(detailsPanel, atLeastOnce()).loadHtml(htmlCaptor.capture());
    assertThat(htmlCaptor.getAllValues().getLast()).contains("Select a dependency to see details.");
  }

  @Test
  void runScan_doesNotRepaintDetailsFromSupersededScan() {
    // Given: two overlapping scans; the first is superseded mid-flight.
    OsvPackage stalePkg = new OsvPackage("stale:pkg", "Maven", "0.1.0");
    OsvPackage currentPkg = new OsvPackage("current:pkg", "Maven", "1.0.0");
    VulnerabilityScannerService.ScanResult staleResult =
        new VulnerabilityScannerService.ScanResult(stalePkg, false, List.of());
    VulnerabilityScannerService.ScanResult currentResult =
        new VulnerabilityScannerService.ScanResult(currentPkg, false, List.of());

    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> stale =
        new CompletableFuture<>();
    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> current =
        new CompletableFuture<>();
    when(scannerService.scanDependencies(true)).thenReturn(stale).thenReturn(current);

    ArgumentCaptor<String> htmlCaptor = ArgumentCaptor.forClass(String.class);

    // When
    vulnSpotterToolWindow.runScan();
    vulnSpotterToolWindow.runScan();
    stale.complete(List.of(staleResult));

    // Then: the superseded scan finished but the preview never got painted from its results.
    verify(detailsPanel, atLeastOnce()).loadHtml(htmlCaptor.capture());
    String last = htmlCaptor.getAllValues().getLast();
    assertThat(last).contains("Select a dependency to see details.");
    assertThat(last).doesNotContain("stale:pkg");

    // When: the current scan finishes.
    current.complete(List.of(currentResult));

    // Then: the table repopulates but the preview stays empty until the user picks a row.
    verify(detailsPanel, atLeastOnce()).loadHtml(htmlCaptor.capture());
    assertThat(htmlCaptor.getAllValues().getLast()).contains("Select a dependency to see details.");
    JBTable table = findResultsTable(vulnSpotterToolWindow.getContent());
    assertNotNull(table);
    assertThat(table.getSelectedRow()).isEqualTo(-1);
  }

  @Test
  void detailsPanel_omitsTreeSectionWhenChainsEmpty() {
    // Given: a vulnerable package with no dependency chains (ecosystems without a dependency tree).
    VulnerabilityScannerService.ScanResult result =
        VulnFixtures.result(
            VulnFixtures.pkg("org.apache.commons:commons-lang3", "3.12.0"),
            true,
            VulnFixtures.dbSeverity("GHSA-test", "HIGH"));
    when(scannerService.scanDependencies(true))
        .thenReturn(CompletableFuture.completedFuture(List.of(result)));

    ArgumentCaptor<String> htmlCaptor = ArgumentCaptor.forClass(String.class);

    // When: the scan finishes and its only row gets selected.
    vulnSpotterToolWindow.runScan();
    JBTable table = findResultsTable(vulnSpotterToolWindow.getContent());
    assertNotNull(table);
    table.setRowSelectionInterval(0, 0);

    // Then: the "Dependency tree" section is absent but the remediation is still painted.
    verify(detailsPanel, atLeastOnce()).loadHtml(htmlCaptor.capture());
    String html = htmlCaptor.getAllValues().getLast();
    assertThat(html).doesNotContain("Dependency tree");
    assertThat(html).contains("remediation-title");
  }
}
