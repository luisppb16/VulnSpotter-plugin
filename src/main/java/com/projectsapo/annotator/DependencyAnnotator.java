/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.annotator;

import com.intellij.lang.annotation.AnnotationHolder;
import com.intellij.lang.annotation.Annotator;
import com.intellij.openapi.project.Project;
import com.intellij.psi.PsiElement;
import com.projectsapo.service.VulnerabilityScannerService;
import org.jetbrains.annotations.NotNull;

public class DependencyAnnotator implements Annotator {

  @Override
  public void annotate(@NotNull PsiElement element, @NotNull AnnotationHolder holder) {
    Project project = element.getProject();
    VulnerabilityScannerService scanner = VulnerabilityScannerService.getInstance(project);
    if (scanner == null) {}

    // Annotation is deferred to future implementation; currently a no-op placeholder
    // so the plugin doesn't crash when registered in plugin.xml.
  }
}
