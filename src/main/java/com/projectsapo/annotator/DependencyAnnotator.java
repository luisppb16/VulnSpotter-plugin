/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.annotator;

import com.intellij.lang.annotation.AnnotationHolder;
import com.intellij.lang.annotation.Annotator;
import com.intellij.lang.annotation.HighlightSeverity;
import com.intellij.psi.PsiElement;
import com.intellij.psi.xml.XmlTag;
import org.jetbrains.annotations.NotNull;

public class DependencyAnnotator implements Annotator {
  @Override
  public void annotate(@NotNull PsiElement element, @NotNull AnnotationHolder holder) {
    if (element instanceof XmlTag tag) {
      if ("dependency".equals(tag.getName())) {
        // Placeholder example logic that uses the quick fix to avoid "never used" warnings
        XmlTag versionTag = tag.findFirstSubTag("version");
        if (versionTag != null) {
          holder
              .newAnnotation(HighlightSeverity.WEAK_WARNING, "Check vulnerability")
              .range(versionTag)
              .newFix(new UpdateDependencyQuickFix("1.0.0-safe"))
              .registerFix()
              .create();
        }
      }
    }
  }
}
