/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.report;

import com.luisppb16.vulnspotter.domain.model.DependencyChainTree;
import com.luisppb16.vulnspotter.util.HtmlEscaper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Renders the dependency chains of one scanned package as a single {@code mvn dependency:tree}
 * listing (shared prefixes collapsed, each chain's last node highlighted) for every consumer that
 * needs the same picture: the tool window preview, the HTML/PDF export and the Markdown export.
 * Returns an empty string when the package carries no chains.
 */
public final class DependencyTreeRenderer {

  /** Child indent under a terminal branch; identical for both glyph sets. */
  private static final String CHILD_INDENT = "   ";

  private DependencyTreeRenderer() {
    throw new UnsupportedOperationException("Utility class");
  }

  public static String renderHtml(
      Set<List<String>> chains,
      Map<String, String> versionIndex,
      String targetVersion,
      String rootLabel,
      Glyphs glyphs) {
    Shape shape = shapeOf(glyphs);
    List<TreeLine> lines = walk(chains, versionIndex, targetVersion, rootLabel, shape);
    if (lines.isEmpty()) {
      return "";
    }
    StringBuilder html = new StringBuilder();
    html.append("<div class='snyk-chain dep-tree'>");
    for (TreeLine line : lines) {
      html.append("<div class='tree-line'>").append(line.prefix());
      if (line.root()) {
        html.append(shape.htmlRootMark).append(HtmlEscaper.escape(line.name()));
      } else if (line.target()) {
        html.append(shape.htmlTargetMark);
        html.append("<b class='target'>").append(HtmlEscaper.escape(line.name()));
        if (line.version() != null) {
          html.append(' ').append(HtmlEscaper.escape(line.version()));
        }
        html.append("</b>");
      } else {
        html.append(shape.htmlChildMark).append(HtmlEscaper.escape(line.name()));
        if (line.version() != null) {
          html.append(' ').append(HtmlEscaper.escape(line.version()));
        }
      }
      html.append("</div>");
    }
    html.append("</div>");
    return html.toString();
  }

  public static String renderText(
      Set<List<String>> chains,
      Map<String, String> versionIndex,
      String targetVersion,
      String rootLabel,
      Glyphs glyphs) {
    List<TreeLine> lines = walk(chains, versionIndex, targetVersion, rootLabel, shapeOf(glyphs));
    if (lines.isEmpty()) {
      return "";
    }
    StringBuilder text = new StringBuilder();
    for (TreeLine line : lines) {
      if (line.target()) {
        text.append(line.prefix()).append(shapeOf(glyphs).textTargetMark());
      } else {
        text.append(line.prefix());
      }
      text.append(line.name());
      if (line.version() != null) {
        text.append(' ').append(line.version());
      }
      text.append('\n');
    }
    return text.toString();
  }

  private static List<TreeLine> walk(
      Set<List<String>> chains,
      Map<String, String> versionIndex,
      String targetVersion,
      String rootLabel,
      Shape shape) {
    List<TreeLine> lines = new ArrayList<>();
    DependencyChainTree.Node root = DependencyChainTree.of(chains).root();
    if (root.children().isEmpty()) {
      return lines;
    }
    lines.add(new TreeLine("", true, false, rootLabel, null));
    walkNodes(root, "", targetVersion, versionIndex, shape, lines);
    return lines;
  }

  private static void walkNodes(
      DependencyChainTree.Node parent,
      String parentPrefix,
      String targetVersion,
      Map<String, String> versionIndex,
      Shape shape,
      List<TreeLine> lines) {
    List<DependencyChainTree.Node> children = parent.children();
    for (int i = 0; i < children.size(); i++) {
      DependencyChainTree.Node node = children.get(i);
      boolean last = i == children.size() - 1;
      lines.add(
          new TreeLine(
              parentPrefix + (last ? shape.last() : shape.branch()),
              false,
              node.target(),
              node.name(),
              node.target() ? targetVersion : versionIndex.get(node.name())));
      walkNodes(
          node,
          parentPrefix + (last ? CHILD_INDENT : shape.mid()),
          targetVersion,
          versionIndex,
          shape,
          lines);
    }
  }

  private static Shape shapeOf(Glyphs glyphs) {
    return glyphs == Glyphs.BOX ? Shape.BOX : Shape.ASCII;
  }

  /** Connectors and marks: BOX for HTML/UI (Unicode, font-dependent) and ASCII for PDF. */
  public enum Glyphs {
    BOX,
    ASCII
  }

  private record TreeLine(
      String prefix, boolean root, boolean target, String name, String version) {}

  private record Shape(
      String branch,
      String last,
      String mid,
      String htmlTargetMark,
      String htmlChildMark,
      String htmlRootMark,
      String textTargetMark) {

    private static final Shape BOX =
        new Shape(
            "├─ ",
            "└─ ",
            "│  ",
            "<span class='icon'>⚠️</span> ",
            "<span class='icon'>📄</span> ",
            "<span class='icon'>📦</span> ",
            "⚠️ ");
    private static final Shape ASCII = new Shape("+- ", "\\- ", "|  ", "[!] ", "", "", "[!] ");
  }
}
