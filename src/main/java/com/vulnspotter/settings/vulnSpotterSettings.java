/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.vulnspotter.settings;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.util.xmlb.XmlSerializerUtil;
import java.util.ArrayList;
import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@State(name = "vulnSpotterSettings", storages = @Storage("vulnspotterSettings.xml"))
public class vulnSpotterSettings implements PersistentStateComponent<vulnSpotterSettings> {

  private int cacheDurationMinutes = 60;
  private String minimumSeverity = "LOW";
  private List<String> ignoredCves = new ArrayList<>();
  private boolean autoScanOnSync = false;

  public static vulnSpotterSettings getInstance() {
    return ApplicationManager.getApplication().getService(vulnSpotterSettings.class);
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
  public vulnSpotterSettings getState() {
    return this;
  }

  @Override
  public void loadState(@NotNull vulnSpotterSettings state) {
    XmlSerializerUtil.copyBean(state, this);
  }
}
