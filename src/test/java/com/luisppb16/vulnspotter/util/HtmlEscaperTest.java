/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("HtmlEscaper Test Suite")
class HtmlEscaperTest {

  @Test
  @DisplayName("should_escape_html_special_characters")
  void shouldEscapeHtmlSpecialCharacters() {
    // Given
    String input = "<script>alert('XSS')</script>";

    // When
    String escaped = HtmlEscaper.escape(input);

    // Then
    assertThat(escaped).isEqualTo("&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;");
  }

  @Test
  @DisplayName("should_escape_ampersand")
  void shouldEscapeAmpersand() {
    // Given
    String input = "Tom & Jerry";

    // When
    String escaped = HtmlEscaper.escape(input);

    // Then
    assertThat(escaped).isEqualTo("Tom &amp; Jerry");
  }

  @Test
  @DisplayName("should_escape_quotes")
  void shouldEscapeQuotes() {
    // Given
    String input = "He said \"Hello\" and 'Goodbye'";

    // When
    String escaped = HtmlEscaper.escape(input);

    // Then
    assertThat(escaped).isEqualTo("He said &quot;Hello&quot; and &#39;Goodbye&#39;");
  }

  @Test
  @DisplayName("should_escape_js_single_quoted_string")
  void shouldEscapeJsSingleQuoted() {
    // Given
    String input = "It's a test with\nnewlines and 'quotes'";

    // When
    String escaped = HtmlEscaper.escapeJsSingleQuoted(input);

    // Then
    assertThat(escaped).isEqualTo("It\\'s a test with\\nnewlines and \\'quotes\\'");
  }

  @Test
  @DisplayName("should_handle_null_input")
  void shouldHandleNullInput() {
    // When
    String escapedHtml = HtmlEscaper.escape(null);
    String escapedJs = HtmlEscaper.escapeJsSingleQuoted(null);

    // Then
    assertThat(escapedHtml).isEmpty();
    assertThat(escapedJs).isEmpty();
  }
}
