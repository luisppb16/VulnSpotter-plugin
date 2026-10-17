/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.sync;

import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskId;
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskType;
import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@DisplayName("ProjectSyncListener Test Suite")
@MockitoSettings(strictness = Strictness.LENIENT)
class ProjectSyncListenerTest {

  @Mock private Project project;
  @Mock private VulnerabilityScannerService scanner;
  @Mock private VulnSpotterSettings settings;
  @Mock private ExternalSystemTaskId taskId;

  private MockedStatic<VulnerabilityScannerService> scannerStatic;
  private MockedStatic<VulnSpotterSettings> settingsStatic;

  private ProjectSyncListener listener;

  @BeforeEach
  void setUp() {
    scannerStatic = mockStatic(VulnerabilityScannerService.class);
    settingsStatic = mockStatic(VulnSpotterSettings.class);

    scannerStatic.when(() -> VulnerabilityScannerService.getInstance(project)).thenReturn(scanner);
    settingsStatic.when(VulnSpotterSettings::getInstance).thenReturn(settings);

    listener = new ProjectSyncListener();
  }

  @AfterEach
  void tearDown() {
    scannerStatic.close();
    settingsStatic.close();
  }

  private void givenSuccessfulResolveTask() {
    when(taskId.getType()).thenReturn(ExternalSystemTaskType.RESOLVE_PROJECT);
    when(taskId.findProject()).thenReturn(project);
  }

  @Test
  @DisplayName("invalidates_osv_cache_after_a_successful_gradle_sync_even_when_auto_scan_is_off")
  void invalidatesOsvCacheAfterASuccessfulGradleSyncEvenWhenAutoScanIsOff() {
    // Given
    givenSuccessfulResolveTask();
    when(settings.isAutoScanOnSync()).thenReturn(false);

    // When
    listener.onSuccess("/path/to/project", taskId);

    // Then
    verify(scanner).invalidateCache();
    verify(scanner, never()).scanDependencies();
  }

  @ParameterizedTest
  @EnumSource(
      value = ExternalSystemTaskType.class,
      mode = EnumSource.Mode.EXCLUDE,
      names = "RESOLVE_PROJECT")
  @DisplayName("ignores_tasks_that_are_not_project_resolutions")
  void ignoresTasksThatAreNotProjectResolutions(ExternalSystemTaskType taskType) {
    // Given
    when(taskId.getType()).thenReturn(taskType);

    // When
    listener.onSuccess("/path/to/project", taskId);

    // Then
    verify(scanner, never()).invalidateCache();
    verify(scanner, never()).scanDependencies();
  }

  @Test
  @DisplayName("does_nothing_when_the_project_is_unavailable")
  void doesNothingWhenTheProjectIsUnavailable() {
    // Given
    givenSuccessfulResolveTask();
    when(taskId.findProject()).thenReturn(null);

    // When
    listener.onSuccess("/path/to/project", taskId);

    // Then
    verify(scanner, never()).invalidateCache();
  }

  @Test
  @DisplayName("invalidates_before_running_the_auto_scan_when_enabled")
  void invalidatesBeforeRunningTheAutoScanWhenEnabled() {
    // Given
    givenSuccessfulResolveTask();
    when(settings.isAutoScanOnSync()).thenReturn(true);
    when(scanner.scanDependencies())
        .thenReturn(CompletableFuture.completedFuture(Collections.emptyList()));

    // When
    listener.onSuccess("/path/to/project", taskId);

    // Then: the scan that follows must re-query OSV on top of a dropped cache.
    InOrder inOrder = inOrder(scanner);
    inOrder.verify(scanner).invalidateCache();
    inOrder.verify(scanner).scanDependencies();
  }
}
