/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.sync;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.intellij.openapi.module.Module;
import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.jetbrains.idea.maven.project.MavenProject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@DisplayName("MavenSyncListener Test Suite")
@MockitoSettings(strictness = Strictness.LENIENT)
class MavenSyncListenerTest {

  @Mock private Project project;
  @Mock private VulnerabilityScannerService scanner;
  @Mock private VulnSpotterSettings settings;

  private MockedStatic<VulnerabilityScannerService> scannerStatic;
  private MockedStatic<VulnSpotterSettings> settingsStatic;

  private MavenSyncListener listener;

  @BeforeEach
  void setUp() {
    scannerStatic = mockStatic(VulnerabilityScannerService.class);
    settingsStatic = mockStatic(VulnSpotterSettings.class);

    scannerStatic.when(() -> VulnerabilityScannerService.getInstance(project)).thenReturn(scanner);
    settingsStatic.when(VulnSpotterSettings::getInstance).thenReturn(settings);
    // A listener test must never reach the real UI plumbing.
    doNothing().when(scanner).updateResults(anyList());

    listener = new MavenSyncListener(project);
  }

  @AfterEach
  void tearDown() {
    scannerStatic.close();
    settingsStatic.close();
  }

  @Test
  @DisplayName("invalidates_osv_cache_after_every_maven_import_even_when_auto_scan_is_off")
  void invalidatesOsvCacheAfterEveryMavenImportEvenWhenAutoScanIsOff() {
    // Given: the default configuration (auto-scan disabled, like the reported session).
    when(settings.isAutoScanOnSync()).thenReturn(false);

    // When
    listener.importFinished(List.of(mock(MavenProject.class)), List.of());

    // Then
    verify(scanner).invalidateCache();
    verify(scanner, never()).scanDependencies();
  }

  @Test
  @DisplayName("invalidates_before_running_the_auto_scan_when_enabled")
  void invalidatesBeforeRunningTheAutoScanWhenEnabled() {
    // Given
    when(settings.isAutoScanOnSync()).thenReturn(true);
    when(scanner.scanDependencies())
        .thenReturn(CompletableFuture.completedFuture(Collections.emptyList()));

    // When
    listener.importFinished(List.of(mock(MavenProject.class)), List.of());

    // Then: the scan that follows must re-query OSV on top of a dropped cache.
    InOrder inOrder = inOrder(scanner);
    inOrder.verify(scanner).invalidateCache();
    inOrder.verify(scanner).scanDependencies();
  }

  @Test
  @DisplayName("skips_everything_when_nothing_was_imported")
  void skipsEverythingWhenNothingWasImported() {
    // When
    listener.importFinished(List.of(), List.of());

    // Then
    verify(scanner, never()).invalidateCache();
    verify(scanner, never()).scanDependencies();
  }

  @Test
  @DisplayName("does_not_throw_when_scanner_service_is_missing")
  void doesNotThrowWhenScannerServiceIsMissing() {
    // Given
    scannerStatic.when(() -> VulnerabilityScannerService.getInstance(project)).thenReturn(null);
    when(settings.isAutoScanOnSync()).thenReturn(false);

    // When / Then: no exception is thrown.
    listener.importFinished(List.of(mock(MavenProject.class)), List.of());
  }
}