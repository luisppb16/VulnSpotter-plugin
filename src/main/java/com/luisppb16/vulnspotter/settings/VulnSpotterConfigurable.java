/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.settings;

import com.intellij.openapi.options.Configurable;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.components.JBTextArea;
import com.intellij.util.ui.FormBuilder;
import com.intellij.util.ui.JBUI;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
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

  @Override
  public @Nls(capitalization = Nls.Capitalization.Title) String getDisplayName() {
    return "VulnSpotter";
  }

  @Override
  public @Nullable JComponent createComponent() {
    autoScanCheckBox = new JBCheckBox("Automatically scan after project sync");
    cacheSpinner = new JSpinner(new SpinnerNumberModel(60, 5, 24 * 60, 5));
    minimumSeverityCombo =
        new JComboBox<>(new String[] {"LOW", "MEDIUM", "HIGH", "CRITICAL"});
    ignoredCvesArea = new JBTextArea(6, 40);
    JBScrollPane ignoredScroll = new JBScrollPane(ignoredCvesArea);

    JBLabel ignoredHint =
        new JBLabel(
            "One vulnerability id per line (CVE-..., GHSA-...). Matching ids and aliases are"
                + " hidden from results.");
    ignoredHint.setForeground(JBUI.CurrentTheme.ContextHelp.FOREGROUND);

    panel =
        FormBuilder.createFormBuilder()
            .addComponent(autoScanCheckBox)
            .addLabeledComponent("Result cache duration (minutes):", cacheSpinner)
            .addLabeledComponent("Minimum severity to report:", minimumSeverityCombo)
            .addLabeledComponent("Ignored vulnerability ids:", ignoredScroll, true)
            .addComponent(ignoredHint)
            .addComponentFillVertically(new JPanel(), 0)
            .getPanel();
    return panel;
  }

  @Override
  public boolean isModified() {
    VulnSpotterSettings settings = VulnSpotterSettings.getInstance();
    return settings.isAutoScanOnSync() != autoScanCheckBox.isSelected()
        || settings.getCacheDurationMinutes() != (Integer) cacheSpinner.getValue()
        || !settings.getMinimumSeverity().equals(minimumSeverityCombo.getSelectedItem())
        || !settings.getIgnoredCves().equals(parseIgnoredCves());
  }

  @Override
  public void apply() {
    VulnSpotterSettings settings = VulnSpotterSettings.getInstance();
    settings.setAutoScanOnSync(autoScanCheckBox.isSelected());
    settings.setCacheDurationMinutes((Integer) cacheSpinner.getValue());
    settings.setMinimumSeverity((String) minimumSeverityCombo.getSelectedItem());
    settings.setIgnoredCves(parseIgnoredCves());
  }

  @Override
  public void reset() {
    VulnSpotterSettings settings = VulnSpotterSettings.getInstance();
    autoScanCheckBox.setSelected(settings.isAutoScanOnSync());
    cacheSpinner.setValue(settings.getCacheDurationMinutes());
    minimumSeverityCombo.setSelectedItem(settings.getMinimumSeverity());
    ignoredCvesArea.setText(String.join("\n", settings.getIgnoredCves()));
  }

  @Override
  public void disposeUIResources() {
    panel = null;
    autoScanCheckBox = null;
    cacheSpinner = null;
    minimumSeverityCombo = null;
    ignoredCvesArea = null;
  }

  private List<String> parseIgnoredCves() {
    return Arrays.stream(ignoredCvesArea.getText().split("\\R"))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .collect(Collectors.toList());
  }
}
