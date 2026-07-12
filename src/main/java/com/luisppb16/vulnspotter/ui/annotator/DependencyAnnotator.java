/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.annotator;

import com.intellij.lang.annotation.AnnotationHolder;
import com.intellij.lang.annotation.Annotator;
import com.intellij.lang.annotation.HighlightSeverity;
import com.intellij.openapi.util.TextRange;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiFile;
import com.intellij.psi.xml.XmlTag;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.service.FixedVersionResolver;
import com.luisppb16.vulnspotter.domain.service.SeverityAnalyzer;
import java.util.Locale;
import org.jetbrains.annotations.NotNull;

/**
 * Highlights vulnerable dependencies in {@code pom.xml} (XML) and {@code build.gradle} (Groovy)
 * using the in-memory results of the last VulnSpotter scan. No network or heavy work happens here;
 * highlighting refreshes automatically after each scan via {@code DaemonCodeAnalyzer.restart()}.
 *
 * <p>The annotation severity reflects the highest vulnerability severity (CRITICAL/HIGH → error
 * stripe, MEDIUM → warning, LOW/UNKNOWN → information), so the editor surfaces the worst issues
 * first.
 */
public class DependencyAnnotator implements Annotator {

  private static final SeverityAnalyzer SEVERITY_ANALYZER = new SeverityAnalyzer();

  private static String stripQuotes(String text) {
    if (text.length() >= 6 && text.startsWith("'''") && text.endsWith("'''")) {
      return text.substring(3, text.length() - 3);
    }
    if (text.length() >= 6 && text.startsWith("\"\"\"") && text.endsWith("\"\"\"")) {
      return text.substring(3, text.length() - 3);
    }
    if (text.length() >= 2 && text.startsWith("'") && text.endsWith("'")) {
      return text.substring(1, text.length() - 1);
    }
    if (text.length() >= 2 && text.startsWith("\"") && text.endsWith("\"")) {
      return text.substring(1, text.length() - 1);
    }
    return text;
  }

  private static HighlightSeverity severityFor(String highest) {
    return switch (highest == null ? "" : highest) {
      case SeverityAnalyzer.CRITICAL, SeverityAnalyzer.HIGH -> HighlightSeverity.ERROR;
      case SeverityAnalyzer.MEDIUM -> HighlightSeverity.WARNING;
      case SeverityAnalyzer.LOW -> HighlightSeverity.INFORMATION;
      default -> HighlightSeverity.WEAK_WARNING;
    };
  }

  @Override
  public void annotate(@NotNull PsiElement element, @NotNull AnnotationHolder holder) {
    PsiFile file = element.getContainingFile();
    if (file == null) {
      return;
    }
    String fileName = file.getName();
    boolean isPom = "pom.xml".equals(fileName);
    boolean isGradle = "build.gradle".equals(fileName);
    if (!isPom && !isGradle) {
      return;
    }

    VulnerabilityScannerService scanner =
        VulnerabilityScannerService.getInstance(element.getProject());
    if (scanner == null || scanner.getLastResults().isEmpty()) {
      return;
    }

    if (isPom) {
      if (element instanceof XmlTag tag && "dependency".equals(tag.getName())) {
        annotatePomDependency(tag, scanner, holder);
      }
    } else {
      annotateGradleLeaf(element, scanner, holder);
    }
  }

  private void annotatePomDependency(
      XmlTag dependencyTag, VulnerabilityScannerService scanner, AnnotationHolder holder) {
    XmlTag groupTag = dependencyTag.findFirstSubTag("groupId");
    XmlTag artifactTag = dependencyTag.findFirstSubTag("artifactId");
    if (groupTag == null || artifactTag == null) {
      return;
    }
    String name =
        groupTag.getValue().getTrimmedText() + ":" + artifactTag.getValue().getTrimmedText();

    XmlTag versionTag = dependencyTag.findFirstSubTag("version");
    String versionText = versionTag != null ? versionTag.getValue().getTrimmedText() : null;
    // A literal version must match the scanned version, otherwise the dependency has already been
    // upgraded past the vulnerable one (a stale scan would otherwise re-highlight a fixed dep).
    // Property-based versions (${...}) cannot be checked here, so they are still annotated.
    String resolvedVersion = null;
    if (versionText != null && !versionText.startsWith("${") && !versionText.endsWith("}")) {
      resolvedVersion = versionText;
    }

    VulnerabilityScannerService.ScanResult result =
        scanner.findVulnerableResult(name, resolvedVersion);
    if (result == null) {
      return;
    }

    // Anchor on the version value text (tighter than the whole tag); fall back to the version tag,
    // then to the artifactId when no version is declared.
    TextRange anchor;
    if (versionTag != null) {
      TextRange valueRange = versionTag.getValue().getTextRange();
      anchor =
          (valueRange != null && !valueRange.isEmpty()) ? valueRange : versionTag.getTextRange();
    } else {
      anchor = artifactTag.getTextRange();
    }
    createAnnotation(holder, anchor, result);
  }

  /**
   * Matches leaf tokens whose text is exactly the vulnerable coordinate "group:artifact:version"
   * (the content token of a Groovy/Kotlin string literal), covering the common {@code
   * implementation 'g:a:v'} notation. Surrounding quotes are stripped because Groovy string-literal
   * leaf tokens include them.
   */
  private void annotateGradleLeaf(
      PsiElement element, VulnerabilityScannerService scanner, AnnotationHolder holder) {
    if (element.getFirstChild() != null) {
      return; // only leaf tokens
    }
    String raw = element.getText();
    if (raw == null || raw.length() < 5) {
      return;
    }
    String text = stripQuotes(raw);
    if (text.indexOf(':') < 0) {
      return;
    }
    int lastColon = text.lastIndexOf(':');
    if (lastColon <= 0 || lastColon == text.length() - 1) {
      return;
    }
    String name = text.substring(0, lastColon);
    String version = text.substring(lastColon + 1);

    VulnerabilityScannerService.ScanResult result = scanner.findVulnerableResult(name, version);
    if (result == null) {
      return;
    }
    createAnnotation(holder, element.getTextRange(), result);
  }

  private void createAnnotation(
      AnnotationHolder holder, TextRange anchor, VulnerabilityScannerService.ScanResult result) {
    int count = result.vulnerabilities().size();
    String highest = SEVERITY_ANALYZER.getHighestSeverity(result.vulnerabilities());
    String fix =
        FixedVersionResolver.recommendUpgrade(
                result.vulnerabilities(), result.pkg().name(), result.pkg().version())
            .orElse(null);

    StringBuilder message = new StringBuilder("VulnSpotter: ");
    message
        .append(count)
        .append(count == 1 ? " known vulnerability" : " known vulnerabilities")
        .append(" (highest severity: ")
        .append(highest.toLowerCase(Locale.ROOT))
        .append(")");
    if (fix != null) {
      message.append(". Recommended version: ").append(fix);
    }

    var builder = holder.newAnnotation(severityFor(highest), message.toString()).range(anchor);
    if (fix != null) {
      builder =
          builder.withFix(
              new UpdateDependencyQuickFix(result.pkg().name(), result.pkg().version(), fix));
    }
    builder.create();
  }
}
