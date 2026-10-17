/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.util;

import java.util.Locale;

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

  /** Escape HTML special characters and turn line breaks into {@code <br/>} tags. */
  public static String escapeWithLineBreaks(String value) {
    if (value == null) {
      return "";
    }
    return escape(value).replace("\n", "<br/>");
  }

  /** Only http(s) links are rendered; javascript:/file: URLs from advisories are dropped. */
  public static boolean isSafeHttpUrl(String url) {
    if (url == null || url.isBlank()) {
      return false;
    }
    String lower = url.trim().toLowerCase(Locale.ROOT);
    return lower.startsWith("http://") || lower.startsWith("https://");
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
