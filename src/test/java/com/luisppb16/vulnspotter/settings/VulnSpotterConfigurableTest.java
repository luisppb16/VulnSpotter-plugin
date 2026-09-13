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
import java.lang.reflect.Field;
import java.util.List;
import javax.swing.JSpinner;
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
    when(settings.isEmailNotificationsEnabled()).thenReturn(false);
    when(settings.getCacheDurationMinutes()).thenReturn(60);
    when(settings.getMinimumSeverity()).thenReturn("LOW");
    when(settings.getIgnoredCves()).thenReturn(List.of());
    when(settings.getNotificationEmail()).thenReturn("");
    when(settings.getEmailSeverities()).thenReturn(List.of("CRITICAL", "HIGH"));
    when(settings.getSmtpHost()).thenReturn("");
    when(settings.getSmtpPort()).thenReturn(587);
    when(settings.getSmtpSecurity()).thenReturn("STARTTLS");
    when(settings.getSmtpUsername()).thenReturn("");
    when(settings.getSmtpPassword()).thenReturn("");

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
    // Given: settings say false but the checkbox defaults to true.
    when(settings.isAnalyzeOnProjectOpen()).thenReturn(false);
    configurable.createComponent();

    // When
    boolean modified = configurable.isModified();
    configurable.apply();

    // Then
    assertThat(modified).isTrue();
    verify(settings).setAnalyzeOnProjectOpen(true);
  }

  @Test
  @DisplayName("should_apply_critical_and_high_when_both_checked")
  void shouldApplyCriticalAndHighWhenBothChecked() {
    // Given: the form with its default CRITICAL + HIGH checkboxes.
    configurable.createComponent();

    // When
    configurable.apply();

    // Then
    verify(settings).setEmailSeverities(List.of("CRITICAL", "HIGH"));
  }

  @Test
  @DisplayName("should_apply_only_low_when_low_is_the_only_checked_box")
  void shouldApplyOnlyLowWhenLowIsTheOnlyCheckedBox() throws Exception {
    // Given: only the Low checkbox is selected.
    configurable.createComponent();
    ((JBCheckBox) component("criticalBox")).setSelected(false);
    ((JBCheckBox) component("highBox")).setSelected(false);
    ((JBCheckBox) component("mediumBox")).setSelected(false);
    ((JBCheckBox) component("lowBox")).setSelected(true);

    // When
    configurable.apply();

    // Then
    verify(settings).setEmailSeverities(List.of("LOW"));
  }

  @Test
  @DisplayName("should_apply_empty_list_when_no_severity_is_checked")
  void shouldApplyEmptyListWhenNoSeverityIsChecked() throws Exception {
    // Given: every severity checkbox is deselected.
    configurable.createComponent();
    ((JBCheckBox) component("criticalBox")).setSelected(false);
    ((JBCheckBox) component("highBox")).setSelected(false);
    ((JBCheckBox) component("mediumBox")).setSelected(false);
    ((JBCheckBox) component("lowBox")).setSelected(false);

    // When
    configurable.apply();

    // Then
    verify(settings).setEmailSeverities(List.of());
  }

  @Test
  @DisplayName("should_load_email_severities_into_checkboxes_on_reset")
  void shouldLoadEmailSeveritiesIntoCheckboxesOnReset() throws Exception {
    // Given: settings carry CRITICAL and MEDIUM only.
    when(settings.getEmailSeverities()).thenReturn(List.of("CRITICAL", "MEDIUM"));
    configurable.createComponent();

    // When
    configurable.reset();

    // Then
    assertThat(((JBCheckBox) component("criticalBox")).isSelected()).isTrue();
    assertThat(((JBCheckBox) component("mediumBox")).isSelected()).isTrue();
    assertThat(((JBCheckBox) component("highBox")).isSelected()).isFalse();
    assertThat(((JBCheckBox) component("lowBox")).isSelected()).isFalse();
  }

  @Test
  @DisplayName("should_apply_smtp_port_from_spinner")
  void shouldApplySmtpPortFromSpinner() throws Exception {
    // Given: the port spinner moved to 465.
    configurable.createComponent();
    ((JSpinner) component("smtpPortSpinner")).setValue(465);

    // When
    configurable.apply();

    // Then
    verify(settings).setSmtpPort(465);
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

  private Object component(String fieldName) throws Exception {
    Field field = VulnSpotterConfigurable.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.get(configurable);
  }
}
