/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.VulnSpotter.settings;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.util.xmlb.XmlSerializerUtil;
import java.util.ArrayList;
import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@State(name = "VulnSpotterSettings", storages = @Storage("VulnSpotterSettings.xml"))
public class VulnSpotterSettings implements PersistentStateComponent<VulnSpotterSettings> {

  private int cacheDurationMinutes = 60;
  private String minimumSeverity = "LOW";
  private List<String> ignoredCves = new ArrayList<>();
  private boolean autoScanOnSync = false;

  public static VulnSpotterSettings getInstance() {
    return ApplicationManager.getApplication().getService(VulnSpotterSettings.class);
  }

  public int getCacheDurationMinutes() {
    return cacheDurationMinutes;
  }

  public void setCacheDurationMinutes(int cacheDurationMinutes) {
    this.cacheDurationMinutes = cacheDurationMinutes;
  }

  public String getMinimumSeverity() {
    return minimumSeverity;
  }

  public void setMinimumSeverity(String minimumSeverity) {
    this.minimumSeverity = minimumSeverity;
  }

  public List<String> getIgnoredCves() {
    return ignoredCves;
  }

  public void setIgnoredCves(List<String> ignoredCves) {
    this.ignoredCves = ignoredCves;
  }

  public boolean isAutoScanOnSync() {
    return autoScanOnSync;
  }

  public void setAutoScanOnSync(boolean autoScanOnSync) {
    this.autoScanOnSync = autoScanOnSync;
  }

  @Nullable
  @Override
  public VulnSpotterSettings getState() {
    return this;
  }

  @Override
  public void loadState(@NotNull VulnSpotterSettings state) {
    XmlSerializerUtil.copyBean(state, this);
  }
}
