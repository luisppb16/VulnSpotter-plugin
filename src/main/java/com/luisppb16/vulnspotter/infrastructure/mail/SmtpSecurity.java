/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.mail;

import java.util.Locale;

/** Transport security used for the SMTP connection. */
public enum SmtpSecurity {
  /** Plain connection, no TLS. */
  NONE,
  /** Plain connection upgraded to TLS with the STARTTLS command. */
  STARTTLS,
  /** TLS handshake from the start (implicit TLS). */
  SSL;

  /**
   * Resolves a security label coming from the settings. Fail-fast: blank or unknown labels are
   * rejected instead of being silently mapped to a default.
   *
   * @param raw label such as {@code "NONE"}, {@code "STARTTLS"} or {@code "SSL"}; case-insensitive
   *     and surrounded whitespace is tolerated.
   * @return the matching constant.
   * @throws IllegalArgumentException if the label is null, blank or unknown.
   */
  public static SmtpSecurity fromLabel(String raw) {
    if (raw == null || raw.isBlank()) {
      throw new IllegalArgumentException("SMTP security label must not be null or blank");
    }
    String label = raw.trim().toUpperCase(Locale.ROOT);
    return switch (label) {
      case "NONE" -> NONE;
      case "STARTTLS" -> STARTTLS;
      case "SSL" -> SSL;
      default -> throw new IllegalArgumentException("Unknown SMTP security label: " + raw);
    };
  }
}