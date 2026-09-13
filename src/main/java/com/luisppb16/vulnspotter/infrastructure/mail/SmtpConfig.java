/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.mail;

/** Immutable SMTP connection settings for a single email alert. */
public record SmtpConfig(
    String host,
    int port,
    SmtpSecurity security,
    String username,
    String password,
    String recipient) {

  /** Compact constructor validating every component; fails fast on invalid input. */
  public SmtpConfig {
    if (host == null || host.isBlank()) {
      throw new IllegalArgumentException("SMTP host must not be null or blank");
    }
    if (security == null) {
      throw new IllegalArgumentException("SMTP security must not be null");
    }
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("SMTP port must be between 1 and 65535, got: " + port);
    }
    if (recipient == null || recipient.isBlank() || !recipient.contains("@")) {
      throw new IllegalArgumentException("SMTP recipient must be a valid email address");
    }
    boolean hasUsername = username != null && !username.isBlank();
    if (hasUsername && password == null) {
      throw new IllegalArgumentException("SMTP password must not be null when username is set");
    }
  }

  /** Convenience constructor for unauthenticated connections (no username/password). */
  public SmtpConfig(String host, int port, SmtpSecurity security, String recipient) {
    this(host, port, security, null, null, recipient);
  }

  /** Returns whether the connection should authenticate with username and password. */
  public boolean requiresAuth() {
    return username != null && !username.isBlank();
  }
}