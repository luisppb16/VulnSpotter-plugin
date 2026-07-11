/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.annotator;

import com.intellij.codeInsight.intention.IntentionAction;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.project.Project;
import com.intellij.psi.PsiFile;
import com.intellij.util.IncorrectOperationException;
import org.jetbrains.annotations.NotNull;

public class UpdateDependencyQuickFix implements IntentionAction {

  @Override
  public @NotNull String getText() {
    return "Update dependency to fixed version";
  }

  @Override
  public @NotNull String getFamilyName() {
    return "VulnSpotter";
  }

  @Override
  public boolean isAvailable(@NotNull Project project, Editor editor, PsiFile file) {
    return false;
  }

  @Override
  public void invoke(@NotNull Project project, Editor editor, PsiFile file)
      throws IncorrectOperationException {
    // Placeholder for future implementation
  }

  @Override
  public boolean startInWriteAction() {
    return true;
  }
}
