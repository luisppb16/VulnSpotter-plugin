/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.annotator;

import com.intellij.codeInsight.intention.IntentionAction;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.project.Project;
import com.intellij.psi.PsiFile;
import com.intellij.util.IncorrectOperationException;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.NotNull;

public class UpdateDependencyQuickFix implements IntentionAction {
  private final String safeVersion;

  public UpdateDependencyQuickFix(String safeVersion) {
    this.safeVersion = safeVersion;
  }

  @Nls(capitalization = Nls.Capitalization.Sentence)
  @NotNull
  @Override
  public String getText() {
    return "Update to safe version " + safeVersion;
  }

  @NotNull
  @Override
  public String getFamilyName() {
    return "Update dependency";
  }

  @Override
  public boolean isAvailable(@NotNull Project project, Editor editor, PsiFile file) {
    return true;
  }

  @Override
  public void invoke(@NotNull Project project, Editor editor, PsiFile file)
      throws IncorrectOperationException {
    // Implement dependency replacement logic
  }

  @Override
  public boolean startInWriteAction() {
    return true;
  }
}
