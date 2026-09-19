/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.startup;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.domain.service.SeverityAnalyzer;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import com.luisppb16.vulnspotter.ui.notification.VulnSpotterNotifications;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ProjectOpenScanActivityTest {

  @Mock private VulnSpotterSettings settings;
  @Mock private VulnerabilityScannerService scanner;
  @Mock private Project project;
  @Mock private Continuation<Unit> continuation;

  private MockedStatic<VulnSpotterSettings> settingsMock;
  private MockedStatic<VulnerabilityScannerService> scannerMock;
  private MockedStatic<VulnSpotterNotifications> notificationsMock;

  private ProjectOpenScanActivity activity;

  private static OsvVulnerability vulnerabilityWithDatabaseSeverity(String severity) {
    return new OsvVulnerability(
        "CVE-2026-0001",
        "Vulnerable dependency",
        null,
        null,
        null,
        null,
        Map.of("severity", severity));
  }

  private static OsvVulnerability vulnerabilityWithoutSeverity() {
    return new OsvVulnerability("CVE-2026-0002", null, null, null, null, null, null);
  }

  private static VulnerabilityScannerService.ScanResult scanResult(OsvVulnerability... vulns) {
    OsvPackage pkg = new OsvPackage("com.example:library", "Maven", "1.0.0");
    return new VulnerabilityScannerService.ScanResult(pkg, vulns.length > 0, List.of(vulns));
  }

  @BeforeEach
  void setUp() {
    settingsMock = mockStatic(VulnSpotterSettings.class);
    scannerMock = mockStatic(VulnerabilityScannerService.class);
    notificationsMock = mockStatic(VulnSpotterNotifications.class);

    activity = new ProjectOpenScanActivity();

    settingsMock.when(VulnSpotterSettings::getInstance).thenReturn(settings);
    when(settings.isAnalyzeOnProjectOpen()).thenReturn(true);
    when(project.isDisposed()).thenReturn(false);
    scannerMock.when(() -> VulnerabilityScannerService.getInstance(project)).thenReturn(scanner);
  }

  @AfterEach
  void tearDown() {
    settingsMock.close();
    scannerMock.close();
    notificationsMock.close();
  }

  private List<VulnerabilityScannerService.ScanResult> stubSuccessfulScan(
      OsvVulnerability... vulns) {
    List<VulnerabilityScannerService.ScanResult> results = List.of(scanResult(vulns));
    when(scanner.scanDependencies()).thenReturn(CompletableFuture.completedFuture(results));
    return results;
  }

  @Test
  @DisplayName("execute skips the scan when the settings service is not available")
  void executeSkipsScanWhenSettingsServiceMissing() {
    // Given: a headless application without the settings service.
    settingsMock.when(VulnSpotterSettings::getInstance).thenReturn(null);

    // When: the project-open activity runs.
    Object result = activity.execute(project, continuation);

    // Then: the scan is never triggered.
    assertThat(result).isEqualTo(Unit.INSTANCE);
    scannerMock.verify(() -> VulnerabilityScannerService.getInstance(project), never());
  }

  @Test
  @DisplayName("execute skips the scan when analyze-on-project-open is disabled")
  void executeSkipsScanWhenDisabled() {
    // Given: the toggle is off.
    when(settings.isAnalyzeOnProjectOpen()).thenReturn(false);

    // When: the project-open activity runs.
    Object result = activity.execute(project, continuation);

    // Then: the scan is never triggered.
    assertThat(result).isEqualTo(Unit.INSTANCE);
    scannerMock.verify(() -> VulnerabilityScannerService.getInstance(project), never());
  }

  @Test
  @DisplayName("execute skips the scan when the scanner service is not available")
  void executeSkipsScanWhenScannerServiceMissing() {
    // Given: the toggle is on but the project scanner is missing.
    scannerMock.when(() -> VulnerabilityScannerService.getInstance(project)).thenReturn(null);

    // When: the project-open activity runs.
    Object result = activity.execute(project, continuation);

    // Then: no scan is started.
    assertThat(result).isEqualTo(Unit.INSTANCE);
    verify(scanner, never()).scanDependencies();
  }

  @Test
  @DisplayName("execute scans when enabled and stores the results")
  void executeScansAndStoresResultsWhenEnabled() {
    // Given: the toggle is on and the scan completes without critical findings.
    List<VulnerabilityScannerService.ScanResult> results =
        stubSuccessfulScan(vulnerabilityWithDatabaseSeverity(SeverityAnalyzer.HIGH));

    // When: the project-open activity runs.
    Object result = activity.execute(project, continuation);

    // Then: the scan runs, the results are stored and no critical warning is shown.
    assertThat(result).isEqualTo(Unit.INSTANCE);
    scannerMock.verify(() -> VulnerabilityScannerService.getInstance(project));
    verify(scanner).scanDependencies();
    verify(scanner).updateResults(results);
    notificationsMock.verify(
        () -> VulnSpotterNotifications.notifyWarning(any(), anyString(), anyString()), never());
  }

  @Test
  @DisplayName("execute warns the user when the scan finds a critical vulnerability")
  void executeWarnsOnCriticalResults() {
    // Given: the toggle is on and the scan completes with a critical finding.
    List<VulnerabilityScannerService.ScanResult> results =
        stubSuccessfulScan(vulnerabilityWithDatabaseSeverity(SeverityAnalyzer.CRITICAL));

    // When: the project-open activity runs.
    Object result = activity.execute(project, continuation);

    // Then: a warning balloon is shown.
    assertThat(result).isEqualTo(Unit.INSTANCE);
    verify(scanner).updateResults(results);
    notificationsMock.verify(
        () -> VulnSpotterNotifications.notifyWarning(eq(project), anyString(), anyString()));
  }

  @Test
  @DisplayName("hasCriticalResults is true when a result carries a critical vulnerability")
  void hasCriticalResultsTrueForCritical() {
    // Given: a result whose highest severity is CRITICAL.
    List<VulnerabilityScannerService.ScanResult> results =
        List.of(scanResult(vulnerabilityWithDatabaseSeverity(SeverityAnalyzer.CRITICAL)));

    // When / Then: the activity reports critical results.
    assertThat(ProjectOpenScanActivity.hasCriticalResults(results)).isTrue();
  }

  @Test
  @DisplayName("hasCriticalResults is false when no result carries a critical severity")
  void hasCriticalResultsFalseWithoutCritical() {
    // Given: results whose severities are below CRITICAL.
    List<VulnerabilityScannerService.ScanResult> results =
        List.of(
            scanResult(vulnerabilityWithDatabaseSeverity(SeverityAnalyzer.HIGH)),
            scanResult(vulnerabilityWithDatabaseSeverity(SeverityAnalyzer.LOW)));

    // When / Then: no critical result is reported.
    assertThat(ProjectOpenScanActivity.hasCriticalResults(results)).isFalse();
  }

  @Test
  @DisplayName("hasCriticalResults is false when vulnerabilities carry no severity data")
  void hasCriticalResultsFalseWithoutSeverityData() {
    // Given: a result whose only vulnerability has neither CVSS nor database_specific severity.
    List<VulnerabilityScannerService.ScanResult> results =
        List.of(scanResult(vulnerabilityWithoutSeverity()));

    // When / Then: the severity is UNKNOWN, never CRITICAL.
    assertThat(ProjectOpenScanActivity.hasCriticalResults(results)).isFalse();
  }

  @Test
  @DisplayName("hasCriticalResults is false for null results")
  void hasCriticalResultsFalseForNull() {
    // Given / When / Then: null results are handled safely.
    assertThat(ProjectOpenScanActivity.hasCriticalResults(null)).isFalse();
  }
}
