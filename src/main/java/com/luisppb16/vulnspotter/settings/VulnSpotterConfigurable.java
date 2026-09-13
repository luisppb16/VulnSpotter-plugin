/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.settings;

import com.intellij.openapi.options.Configurable;
import com.intellij.ui.TitledSeparator;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBPasswordField;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.components.JBTextArea;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.FormBuilder;
import com.intellij.util.ui.JBUI;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

/** Settings page (Settings | Tools | VulnSpotter) backed by {@link VulnSpotterSettings}. */
public class VulnSpotterConfigurable implements Configurable {

  private JPanel panel;
  private JBCheckBox autoScanCheckBox;
  private JSpinner cacheSpinner;
  private JComboBox<String> minimumSeverityCombo;
  private JBTextArea ignoredCvesArea;
  private JBCheckBox analyzeOnOpenCheckBox;
  private JBCheckBox emailEnabledCheckBox;
  private JBTextField emailField;
  private JBCheckBox criticalBox;
  private JBCheckBox highBox;
  private JBCheckBox mediumBox;
  private JBCheckBox lowBox;
  private JBTextField smtpHostField;
  private JSpinner smtpPortSpinner;
  private JComboBox<String> smtpSecurityCombo;
  private JBTextField smtpUserField;
  private JBPasswordField smtpPasswordField;

  @Override
  public @Nls(capitalization = Nls.Capitalization.Title) String getDisplayName() {
    return "VulnSpotter";
  }

  @Override
  public @Nullable JComponent createComponent() {
    autoScanCheckBox = new JBCheckBox("Automatically scan after project sync");
    analyzeOnOpenCheckBox = new JBCheckBox("Automatically analyze on project open");
    analyzeOnOpenCheckBox.setSelected(true);
    cacheSpinner = new JSpinner(new SpinnerNumberModel(60, 5, 24 * 60, 5));
    minimumSeverityCombo = new JComboBox<>(new String[] {"LOW", "MEDIUM", "HIGH", "CRITICAL"});
    ignoredCvesArea = new JBTextArea(6, 40);
    JBScrollPane ignoredScroll = new JBScrollPane(ignoredCvesArea);

    JBLabel ignoredHint =
        new JBLabel(
            "One vulnerability id per line (CVE-..., GHSA-...). Matching ids and aliases are"
                + " hidden from results.");
    ignoredHint.setForeground(JBUI.CurrentTheme.ContextHelp.FOREGROUND);

    emailEnabledCheckBox = new JBCheckBox("Send email alerts");
    emailField = new JBTextField();
    criticalBox = new JBCheckBox("Critical", true);
    highBox = new JBCheckBox("High", true);
    mediumBox = new JBCheckBox("Medium");
    lowBox = new JBCheckBox("Low");
    JPanel severitiesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
    severitiesPanel.add(criticalBox);
    severitiesPanel.add(highBox);
    severitiesPanel.add(mediumBox);
    severitiesPanel.add(lowBox);

    smtpHostField = new JBTextField();
    smtpPortSpinner = new JSpinner(new SpinnerNumberModel(587, 1, 65535, 1));
    smtpSecurityCombo = new JComboBox<>(new String[] {"NONE", "STARTTLS", "SSL"});
    smtpUserField = new JBTextField();
    smtpPasswordField = new JBPasswordField();

    JBLabel passwordHint =
        new JBLabel(
            "Stored in plain text in the IDE settings file. Do not reuse a personal password.");
    passwordHint.setForeground(JBUI.CurrentTheme.ContextHelp.FOREGROUND);

    panel =
        FormBuilder.createFormBuilder()
            .addComponent(autoScanCheckBox)
            .addComponent(analyzeOnOpenCheckBox)
            .addLabeledComponent("Result cache duration (minutes):", cacheSpinner)
            .addLabeledComponent("Minimum severity to report:", minimumSeverityCombo)
            .addLabeledComponent("Ignored vulnerability ids:", ignoredScroll, true)
            .addComponent(ignoredHint)
            .addComponent(new TitledSeparator("Email alerts"))
            .addComponent(emailEnabledCheckBox)
            .addLabeledComponent("Recipient email:", emailField)
            .addLabeledComponent("Severities:", severitiesPanel)
            .addLabeledComponent("SMTP host:", smtpHostField)
            .addLabeledComponent("SMTP port:", smtpPortSpinner)
            .addLabeledComponent("SMTP security:", smtpSecurityCombo)
            .addLabeledComponent("SMTP username:", smtpUserField)
            .addLabeledComponent("SMTP password:", smtpPasswordField)
            .addComponent(passwordHint)
            .addComponentFillVertically(new JPanel(), 0)
            .getPanel();
    return panel;
  }

  @Override
  public boolean isModified() {
    VulnSpotterSettings settings = VulnSpotterSettings.getInstance();
    return settings.isAutoScanOnSync() != autoScanCheckBox.isSelected()
        || settings.isAnalyzeOnProjectOpen() != analyzeOnOpenCheckBox.isSelected()
        || settings.getCacheDurationMinutes() != (Integer) cacheSpinner.getValue()
        || !settings.getMinimumSeverity().equals(minimumSeverityCombo.getSelectedItem())
        || !settings.getIgnoredCves().equals(parseIgnoredCves())
        || settings.isEmailNotificationsEnabled() != emailEnabledCheckBox.isSelected()
        || !settings.getNotificationEmail().equals(emailField.getText())
        || !Set.copyOf(settings.getEmailSeverities()).equals(parseSelectedSeverities())
        || !settings.getSmtpHost().equals(smtpHostField.getText())
        || settings.getSmtpPort() != (Integer) smtpPortSpinner.getValue()
        || !settings.getSmtpSecurity().equals(smtpSecurityCombo.getSelectedItem())
        || !settings.getSmtpUsername().equals(smtpUserField.getText())
        || !settings.getSmtpPassword().equals(String.valueOf(smtpPasswordField.getPassword()));
  }

  @Override
  public void apply() {
    VulnSpotterSettings settings = VulnSpotterSettings.getInstance();
    settings.setAutoScanOnSync(autoScanCheckBox.isSelected());
    settings.setAnalyzeOnProjectOpen(analyzeOnOpenCheckBox.isSelected());
    settings.setCacheDurationMinutes((Integer) cacheSpinner.getValue());
    settings.setMinimumSeverity((String) minimumSeverityCombo.getSelectedItem());
    settings.setIgnoredCves(parseIgnoredCves());
    settings.setEmailNotificationsEnabled(emailEnabledCheckBox.isSelected());
    settings.setNotificationEmail(emailField.getText());
    settings.setEmailSeverities(parseEmailSeverities());
    settings.setSmtpHost(smtpHostField.getText());
    settings.setSmtpPort((Integer) smtpPortSpinner.getValue());
    settings.setSmtpSecurity((String) smtpSecurityCombo.getSelectedItem());
    settings.setSmtpUsername(smtpUserField.getText());
    settings.setSmtpPassword(String.valueOf(smtpPasswordField.getPassword()));
  }

  @Override
  public void reset() {
    VulnSpotterSettings settings = VulnSpotterSettings.getInstance();
    autoScanCheckBox.setSelected(settings.isAutoScanOnSync());
    analyzeOnOpenCheckBox.setSelected(settings.isAnalyzeOnProjectOpen());
    cacheSpinner.setValue(settings.getCacheDurationMinutes());
    minimumSeverityCombo.setSelectedItem(settings.getMinimumSeverity());
    ignoredCvesArea.setText(String.join("\n", settings.getIgnoredCves()));
    emailEnabledCheckBox.setSelected(settings.isEmailNotificationsEnabled());
    emailField.setText(settings.getNotificationEmail());
    List<String> emailSeverities = settings.getEmailSeverities();
    criticalBox.setSelected(emailSeverities.contains("CRITICAL"));
    highBox.setSelected(emailSeverities.contains("HIGH"));
    mediumBox.setSelected(emailSeverities.contains("MEDIUM"));
    lowBox.setSelected(emailSeverities.contains("LOW"));
    smtpHostField.setText(settings.getSmtpHost());
    smtpPortSpinner.setValue(settings.getSmtpPort());
    smtpSecurityCombo.setSelectedItem(settings.getSmtpSecurity());
    smtpUserField.setText(settings.getSmtpUsername());
    smtpPasswordField.setText(settings.getSmtpPassword());
  }

  @Override
  public void disposeUIResources() {
    panel = null;
    autoScanCheckBox = null;
    cacheSpinner = null;
    minimumSeverityCombo = null;
    ignoredCvesArea = null;
    analyzeOnOpenCheckBox = null;
    emailEnabledCheckBox = null;
    emailField = null;
    criticalBox = null;
    highBox = null;
    mediumBox = null;
    lowBox = null;
    smtpHostField = null;
    smtpPortSpinner = null;
    smtpSecurityCombo = null;
    smtpUserField = null;
    smtpPasswordField = null;
  }

  private List<String> parseIgnoredCves() {
    return Arrays.stream(ignoredCvesArea.getText().split("\\R"))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();
  }

  /** Builds the alert severities list in canonical order, keeping only the checked boxes. */
  private List<String> parseEmailSeverities() {
    List<String> severities = new ArrayList<>();
    if (criticalBox.isSelected()) {
      severities.add("CRITICAL");
    }
    if (highBox.isSelected()) {
      severities.add("HIGH");
    }
    if (mediumBox.isSelected()) {
      severities.add("MEDIUM");
    }
    if (lowBox.isSelected()) {
      severities.add("LOW");
    }
    return severities;
  }

  private Set<String> parseSelectedSeverities() {
    Set<String> severities = new HashSet<>();
    if (criticalBox.isSelected()) {
      severities.add("CRITICAL");
    }
    if (highBox.isSelected()) {
      severities.add("HIGH");
    }
    if (mediumBox.isSelected()) {
      severities.add("MEDIUM");
    }
    if (lowBox.isSelected()) {
      severities.add("LOW");
    }
    return severities;
  }
}
