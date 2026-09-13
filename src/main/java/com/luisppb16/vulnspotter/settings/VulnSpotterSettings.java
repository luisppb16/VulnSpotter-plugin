/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.settings;

import com.intellij.openapi.application.Application;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.util.xmlb.XmlSerializerUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@State(name = "VulnSpotterSettings", storages = @Storage("vulnSpotterSettings.xml"))
public class VulnSpotterSettings implements PersistentStateComponent<VulnSpotterSettings> {

  private int cacheDurationMinutes = 60;
  private String minimumSeverity = "LOW";
  private List<String> ignoredCves = new ArrayList<>();
  private boolean autoScanOnSync = false;
  private boolean analyzeOnProjectOpen = true;
  private boolean emailNotificationsEnabled = false;
  private String notificationEmail = "";
  private List<String> emailSeverities = new ArrayList<>(List.of("CRITICAL", "HIGH"));
  private String smtpHost = "";
  private int smtpPort = 587;
  // Valid values: NONE | STARTTLS | SSL.
  private String smtpSecurity = "STARTTLS";
  private String smtpUsername = "";
  // Stored in plain text in the IDE settings file. Do not reuse a personal password.
  private String smtpPassword = "";

  public static VulnSpotterSettings getInstance() {
    Application app = ApplicationManager.getApplication();
    return app != null ? app.getService(VulnSpotterSettings.class) : null;
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

  public boolean isAnalyzeOnProjectOpen() {
    return analyzeOnProjectOpen;
  }

  public void setAnalyzeOnProjectOpen(boolean analyzeOnProjectOpen) {
    this.analyzeOnProjectOpen = analyzeOnProjectOpen;
  }

  public boolean isEmailNotificationsEnabled() {
    return emailNotificationsEnabled;
  }

  public void setEmailNotificationsEnabled(boolean emailNotificationsEnabled) {
    this.emailNotificationsEnabled = emailNotificationsEnabled;
  }

  public String getNotificationEmail() {
    return notificationEmail;
  }

  public void setNotificationEmail(String notificationEmail) {
    this.notificationEmail = notificationEmail;
  }

  public List<String> getEmailSeverities() {
    return emailSeverities;
  }

  public void setEmailSeverities(List<String> emailSeverities) {
    this.emailSeverities = Objects.requireNonNullElse(emailSeverities, new ArrayList<>());
  }

  public String getSmtpHost() {
    return smtpHost;
  }

  public void setSmtpHost(String smtpHost) {
    this.smtpHost = smtpHost;
  }

  public int getSmtpPort() {
    return smtpPort;
  }

  public void setSmtpPort(int smtpPort) {
    this.smtpPort = smtpPort;
  }

  public String getSmtpSecurity() {
    return smtpSecurity;
  }

  public void setSmtpSecurity(String smtpSecurity) {
    this.smtpSecurity = smtpSecurity;
  }

  public String getSmtpUsername() {
    return smtpUsername;
  }

  public void setSmtpUsername(String smtpUsername) {
    this.smtpUsername = smtpUsername;
  }

  public String getSmtpPassword() {
    return smtpPassword;
  }

  public void setSmtpPassword(String smtpPassword) {
    this.smtpPassword = smtpPassword;
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
