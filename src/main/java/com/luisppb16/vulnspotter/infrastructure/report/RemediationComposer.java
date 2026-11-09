/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.report;

import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.model.DependencyProvenance;
import com.luisppb16.vulnspotter.domain.model.ParentRemediation;
import com.luisppb16.vulnspotter.domain.service.FixedVersionResolver;
import com.luisppb16.vulnspotter.util.HtmlEscaper;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Renders the remediation box shared by the tool window details panel and the exported report: the
 * provenance chip, the direct upgrade, the per-root transitive advice (with the generic fallback
 * for roots Maven Central could not deduce) and the platform-provided line. Markup is
 * byte-identical across both surfaces; only the surrounding style rules differ.
 */
public final class RemediationComposer {

  private static final String DIV_CLOSE = "</div>";
  private static final String UNKNOWN = FixedVersionResolver.UNKNOWN;

  private RemediationComposer() {
    throw new UnsupportedOperationException("Utility class");
  }

  public static void append(
      StringBuilder sb,
      VulnerabilityScannerService.ScanResult result,
      String recommended,
      Map<String, String> versionIndex,
      List<ParentRemediation> remediations) {
    sb.append("<div class='remediation-box'>");
    sb.append("<div class='remediation-title'>Remediation</div>");

    DependencyProvenance provenance = DependencyProvenance.of(result.pkg().dependencyChains());
    boolean isDirect =
        provenance.kind() != DependencyProvenance.Kind.TRANSITIVE
            && provenance.kind() != DependencyProvenance.Kind.PROVIDED;
    String fixedVerStr = recommended != null ? recommended : UNKNOWN;

    sb.append("<div class='dep-classification'>")
        .append(HtmlEscaper.escape(classificationLabel(provenance)))
        .append(DIV_CLOSE);

    if (isDirect) {
      appendDirectRemediation(sb, result, fixedVerStr);
    }

    if (!provenance.transitiveRoots().isEmpty()) {
      if (isDirect) {
        sb.append("<hr style='border: 0; border-top: 1px solid #ccc; margin: 8px 0;'/>");
      }
      appendTransitiveRemediation(
          sb, result, fixedVerStr, provenance.transitiveRoots(), versionIndex, remediations);
    }

    if (provenance.kind() == DependencyProvenance.Kind.PROVIDED) {
      sb.append("<p>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append(" is provided by the intellijPlatform toolchain — it ships with the IDE")
          .append(" distribution, so no source-level upgrade applies.</p>");
    }
    sb.append(DIV_CLOSE);
  }

  public static String classificationLabel(DependencyProvenance provenance) {
    return switch (provenance.kind()) {
      case DependencyProvenance.Kind.TRANSITIVE -> "Transitive dependency";
      case DependencyProvenance.Kind.MIXED -> "Direct and transitive dependency";
      case DependencyProvenance.Kind.PROVIDED -> "Provided by the intellijPlatform toolchain";
      default -> "Direct dependency";
    };
  }

  private static void appendDirectRemediation(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result, String fixedVerStr) {
    if (!UNKNOWN.equals(fixedVerStr)) {
      sb.append("<p>Upgrade <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append("</b> to version <b>")
          .append(HtmlEscaper.escape(fixedVerStr))
          .append("</b>");
      sb.append(VulnerabilityCardComposer.copyButton(fixedVerStr)).append("</p>");
    } else {
      sb.append("<p>No fixed version available for <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append("</b> at this time.</p>");
    }
  }

  private static void appendTransitiveRemediation(
      StringBuilder sb,
      VulnerabilityScannerService.ScanResult result,
      String fixedVerStr,
      List<String> roots,
      Map<String, String> versionIndex,
      List<ParentRemediation> remediations) {
    Map<String, ParentRemediation> byRoot = new HashMap<>();
    remediations.forEach(remediation -> byRoot.putIfAbsent(remediation.root(), remediation));
    if (!UNKNOWN.equals(fixedVerStr)) {
      roots.forEach(root -> {
        if (DependencyProvenance.isPlatformRoot(root)) {
          return;
        }
        ParentRemediation remediation = byRoot.get(root);
        if (remediation != null && remediation.targetVersion() != null) {
          sb.append("<p>To fix transitively, upgrade <code>")
              .append(HtmlEscaper.escape(remediation.rootWithVersion()))
              .append("</code> to <b>")
              .append(HtmlEscaper.escape(remediation.targetVersion()))
              .append("</b> (ships <b>")
              .append(HtmlEscaper.escape(result.pkg().name()))
              .append("</b> ")
              .append(HtmlEscaper.escape(remediation.shipsChildVersion()))
              .append(")");
          sb.append(VulnerabilityCardComposer.copyButton(remediation.targetVersion()));
          sb.append("</p>");
        } else {
          sb.append("<p>Upgrade <code>")
              .append(HtmlEscaper.escape(rootWithVersion(root, versionIndex)))
              .append("</code> to a version that uses <b>")
              .append(HtmlEscaper.escape(result.pkg().name()))
              .append("</b> version <b>")
              .append(HtmlEscaper.escape(fixedVerStr))
              .append("</b> or later.</p>");
        }
      });
    } else {
      sb.append("<p>Transitive dependency <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append("</b> has no fixed version available.</p>");
      sb.append("<p>Affected roots:</p><ul>");
      roots.stream()
          .filter(root -> !DependencyProvenance.isPlatformRoot(root))
          .forEach(root ->
              sb.append("<li><code>")
                  .append(HtmlEscaper.escape(rootWithVersion(root, versionIndex)))
                  .append("</code></li>"));
      sb.append("</ul>");
    }
  }

  private static String rootWithVersion(String root, Map<String, String> versionIndex) {
    String version = versionIndex.get(root);
    return version == null ? root : root + " " + version;
  }
}
