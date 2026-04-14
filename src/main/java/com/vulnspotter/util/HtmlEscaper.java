/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.vulnspotter.util;

/** Utility for HTML escaping and encoding. */
public final class HtmlEscaper {

  private HtmlEscaper() {
    throw new UnsupportedOperationException("Utility class");
  }

  /** Escape HTML special characters to prevent injection. */
  public static String escape(String value) {
    if (value == null) {
      return "";
    }
    return value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;");
  }

  /** Escape string for use in JavaScript single-quoted context. */
  public static String escapeJsSingleQuoted(String value) {
    if (value == null) {
      return "";
    }
    return value
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r");
  }
}
