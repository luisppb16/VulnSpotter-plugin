/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.settings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.intellij.ui.components.JBCheckBox;
import java.awt.Component;
import java.awt.Container;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("VulnSpotterConfigurable Test Suite")
class VulnSpotterConfigurableTest {

  private VulnSpotterSettings settings;
  private MockedStatic<VulnSpotterSettings> settingsMock;
  private VulnSpotterConfigurable configurable;

  @BeforeEach
  void setUp() {
    settings = mock(VulnSpotterSettings.class);
    settingsMock = mockStatic(VulnSpotterSettings.class);
    settingsMock.when(VulnSpotterSettings::getInstance).thenReturn(settings);

    // Given: settings holding the same values the UI defaults to.
    when(settings.isAutoScanOnSync()).thenReturn(false);
    when(settings.isAnalyzeOnProjectOpen()).thenReturn(true);
    when(settings.getCacheDurationMinutes()).thenReturn(60);
    when(settings.isDisableVulnerabilityCache()).thenReturn(false);
    when(settings.getMinimumSeverity()).thenReturn("LOW");
    when(settings.getIgnoredCves()).thenReturn(List.of());

    configurable = new VulnSpotterConfigurable();
  }

  @AfterEach
  void tearDown() {
    settingsMock.close();
  }

  @Test
  @DisplayName("should_not_be_modified_when_settings_match_ui_defaults")
  void shouldNotBeModifiedWhenSettingsMatchUiDefaults() throws Exception {
    // Given: settings with default values and a freshly built, reset form.
    configurable.createComponent();
    configurable.reset();

    // When
    boolean modified = configurable.isModified();

    // Then
    assertThat(modified).isFalse();
  }

  @Test
  @DisplayName("should_detect_and_apply_changed_analyze_on_project_open")
  void shouldDetectAndApplyChangedAnalyzeOnProjectOpen() throws Exception {
    // Given: settings say on but the fresh form starts unchecked (the new factory default).
    when(settings.isAnalyzeOnProjectOpen()).thenReturn(true);
    configurable.createComponent();

    // When
    boolean modified = configurable.isModified();
    configurable.apply();

    // Then: the form stores its own (unchecked) state over the changed setting.
    assertThat(modified).isTrue();
    verify(settings).setAnalyzeOnProjectOpen(false);
  }

  @Test
  @DisplayName("should_survive_recreate_component_after_dispose")
  void shouldSurviveRecreateComponentAfterDispose() {
    // Given: a disposed form.
    configurable.createComponent();
    configurable.disposeUIResources();

    // When: the form is rebuilt and queried again.
    // Then: no stale state leaks and nothing throws.
    assertThatCode(
            () -> {
              configurable.createComponent();
              configurable.isModified();
            })
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("should_detect_and_apply_changed_disable_vulnerability_cache")
  void shouldDetectAndApplyChangedDisableVulnerabilityCache() throws Exception {
    // Given: the stored value is off but the form checkbox is ticked.
    JBCheckBox disableCacheCheckBox = findDisableCacheCheckBox(configurable.createComponent());
    assertThat(disableCacheCheckBox).isNotNull();
    disableCacheCheckBox.setSelected(true);

    // When
    boolean modified = configurable.isModified();
    configurable.apply();

    // Then
    assertThat(modified).isTrue();
    verify(settings).setDisableVulnerabilityCache(true);
  }

  @Test
  @DisplayName("should_reset_disable_vulnerability_cache_from_stored_value")
  void shouldResetDisableVulnerabilityCacheFromStoredValue() throws Exception {
    // Given: a stored on-value and a freshly built form whose checkbox starts unchecked.
    when(settings.isDisableVulnerabilityCache()).thenReturn(true);
    JBCheckBox disableCacheCheckBox = findDisableCacheCheckBox(configurable.createComponent());
    assertThat(disableCacheCheckBox.isSelected()).isFalse();

    // When
    configurable.reset();

    // Then: the checkbox mirrors the stored value and the form reports no pending change.
    assertThat(disableCacheCheckBox.isSelected()).isTrue();
    assertThat(configurable.isModified()).isFalse();
  }

  private JBCheckBox findDisableCacheCheckBox(Container container) {
    for (Component component : container.getComponents()) {
      if (component instanceof JBCheckBox box
          && box.getText().startsWith("Disable vulnerability caching")) {
        return box;
      }
      if (component instanceof Container child) {
        JBCheckBox found = findDisableCacheCheckBox(child);
        if (found != null) {
          return found;
        }
      }
    }
    return null;
  }
}
