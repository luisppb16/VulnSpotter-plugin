/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.report;

import static org.assertj.core.api.Assertions.assertThat;

import com.luisppb16.vulnspotter.infrastructure.report.DependencyTreeRenderer.Glyphs;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DependencyTreeRenderer Test Suite")
class DependencyTreeRendererTest {

  @Test
  @DisplayName("renders_the_merged_tree_with_the_project_root_and_the_target_marked")
  void rendersTheMergedTreeWithTheProjectRootAndTheTargetMarked() {
    String html =
        DependencyTreeRenderer.renderHtml(
            Set.of(
                List.of(
                    "org.springframework:spring-boot-starter-web",
                    "com.fasterxml.jackson.core:jackson-databind"),
                List.of(
                    "io.projectreactor:reactor-netty",
                    "com.fasterxml.jackson.core:jackson-databind")),
            Map.of("com.fasterxml.jackson.core:jackson-databind", "2.9.0"),
            "2.9.0",
            "sample-web-app",
            Glyphs.BOX);

    assertThat(html)
        .isEqualTo(
            "<div class='snyk-chain dep-tree'>"
                + "<div class='tree-line'><span class='icon'>📦</span> sample-web-app</div>"
                + "<div class='tree-line'>├─ <span class='icon'>📄</span> "
                + "io.projectreactor:reactor-netty</div>"
                + "<div class='tree-line'>│  └─ <span class='icon'>⚠️</span> "
                + "<b class='target'>com.fasterxml.jackson.core:jackson-databind 2.9.0</b></div>"
                + "<div class='tree-line'>└─ <span class='icon'>📄</span> "
                + "org.springframework:spring-boot-starter-web</div>"
                + "<div class='tree-line'>   └─ <span class='icon'>⚠️</span> "
                + "<b class='target'>com.fasterxml.jackson.core:jackson-databind 2.9.0</b></div>"
                + "</div>");
  }

  @Test
  @DisplayName("returns_an_empty_section_when_chains_are_empty")
  void returnsAnEmptySectionWhenChainsAreEmpty() {
    assertThat(
            DependencyTreeRenderer.renderHtml(Set.of(), Map.of(), "1.0.0", "project", Glyphs.BOX))
        .isEmpty();
    assertThat(
            DependencyTreeRenderer.renderText(Set.of(), Map.of(), "1.0.0", "project", Glyphs.BOX))
        .isEmpty();
  }

  @Test
  @DisplayName("renders_ascii_connectors_and_marks_for_the_pdf_export")
  void rendersAsciiConnectorsAndMarksForThePdfExport() {
    String html =
        DependencyTreeRenderer.renderHtml(
            Set.of(List.of("a:b", "t:c")), Map.of("a:b", "1.0"), "2.0", "project", Glyphs.ASCII);

    assertThat(html)
        .isEqualTo(
            "<div class='snyk-chain dep-tree'>"
                + "<div class='tree-line'>project</div>"
                + "<div class='tree-line'>\\- a:b 1.0</div>"
                + "<div class='tree-line'>   \\- [!] <b class='target'>t:c 2.0</b></div>"
                + "</div>");
    assertThat(html)
        .doesNotContain("├─")
        .doesNotContain("└─")
        .doesNotContain("│")
        .doesNotContain("span");
  }

  @Test
  @DisplayName("renders_the_plain_text_tree_for_markdown")
  void rendersThePlainTextTreeForMarkdown() {
    String text =
        DependencyTreeRenderer.renderText(
            Set.of(List.of("a:b", "t:c"), List.of("d:e", "t:c")),
            Map.of("a:b", "1.0"),
            "2.0",
            "project",
            Glyphs.BOX);

    assertThat(text)
        .isEqualTo(
            "project\n"
                + "├─ a:b 1.0\n"
                + "│  └─ ⚠️ t:c 2.0\n"
                + "└─ d:e\n"
                + "   └─ ⚠️ t:c 2.0\n");
  }

  @Test
  @DisplayName("escapes_node_names_and_root_label_in_html_but_keeps_text_raw")
  void escapesNodeNamesAndRootLabelInHtmlButKeepsTextRaw() {
    String html =
        DependencyTreeRenderer.renderHtml(
            Set.of(List.of("evil&pkg", "a<b:c")), Map.of(), "1.0", "root&label", Glyphs.BOX);

    assertThat(html).contains("<span class='icon'>📦</span> root&amp;label");
    assertThat(html).contains("evil&amp;pkg");
    assertThat(html).contains("a&lt;b:c");

    String text =
        DependencyTreeRenderer.renderText(
            Set.of(List.of("a<b:c")), Map.of(), "1.0", "root&label", Glyphs.BOX);
    assertThat(text).contains("a<b:c");
  }
}
