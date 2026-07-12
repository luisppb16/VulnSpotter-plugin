/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.annotator;

import com.intellij.codeInsight.intention.IntentionAction;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.project.Project;
import com.intellij.psi.PsiDocumentManager;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiFile;
import com.intellij.psi.XmlElementFactory;
import com.intellij.psi.util.PsiTreeUtil;
import com.intellij.psi.xml.XmlFile;
import com.intellij.psi.xml.XmlTag;
import com.intellij.util.IncorrectOperationException;
import com.luisppb16.vulnspotter.domain.service.VersionUtil;
import org.jetbrains.annotations.NotNull;

/**
 * Quick fix attached to VulnSpotter annotations: updates the dependency declaration to the
 * recommended fixed version.
 *
 * <p>In {@code pom.xml} it edits the {@code <version>} tag (or the property definition when the
 * version is declared through {@code ${my.version}}); when no {@code <version>} sub-tag exists it
 * inserts one. In {@code build.gradle} it replaces the literal {@code group:artifact:version}
 * coordinate, bounded so it never corrupts a longer token. The fix refuses to downgrade a
 * dependency that is already at or above the target version, and tells the user when the version is
 * declared indirectly (property/catalog) and cannot be auto-upgraded.
 */
public class UpdateDependencyQuickFix implements IntentionAction {

  private static final String NOTIFICATION_GROUP_ID = "VulnSpotter Notifications";

  private final String packageName; // "group:artifact"
  private final String currentVersion;
  private final String targetVersion;

  public UpdateDependencyQuickFix(String packageName, String currentVersion, String targetVersion) {
    this.packageName = packageName;
    this.currentVersion = currentVersion;
    this.targetVersion = targetVersion;
  }

  /** Characters that may appear inside a group:artifact:version coordinate token. */
  private static boolean isCoordinateChar(char c) {
    return (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == ':'
        || c == '.'
        || c == '-'
        || c == '+'
        || c == '_'
        || c == '~'
        || c == '^'
        || c == '/';
  }

  private static void notify(Project project, String message, NotificationType type) {
    NotificationGroupManager.getInstance()
        .getNotificationGroup(NOTIFICATION_GROUP_ID)
        .createNotification("VulnSpotter", message, type)
        .notify(project);
  }

  @Override
  public @NotNull String getText() {
    return "Update " + artifactId() + " to " + targetVersion;
  }

  @Override
  public @NotNull String getFamilyName() {
    return "VulnSpotter";
  }

  private String artifactId() {
    int idx = packageName.lastIndexOf(':');
    return idx >= 0 ? packageName.substring(idx + 1) : packageName;
  }

  @Override
  public boolean isAvailable(@NotNull Project project, Editor editor, PsiFile file) {
    return file != null
        && ("pom.xml".equals(file.getName()) || "build.gradle".equals(file.getName()));
  }

  @Override
  public void invoke(@NotNull Project project, Editor editor, PsiFile file)
      throws IncorrectOperationException {
    if (file instanceof XmlFile xmlFile) {
      updatePom(project, xmlFile, editor);
    } else {
      updateGradle(project, file);
    }
  }

  private void updatePom(Project project, XmlFile file, Editor editor) {
    XmlTag dependencyTag = findDependencyTag(file, editor);
    if (dependencyTag == null) {
      notify(
          project,
          "Could not locate the <dependency> declaration for " + packageName + ".",
          NotificationType.WARNING);
      return;
    }
    XmlTag versionTag = dependencyTag.findFirstSubTag("version");
    String versionText = versionTag != null ? versionTag.getValue().getTrimmedText() : null;

    if (versionText != null && versionText.startsWith("${") && versionText.endsWith("}")) {
      String propertyName = versionText.substring(2, versionText.length() - 1);
      XmlTag root = file.getRootTag();
      XmlTag properties = root != null ? root.findFirstSubTag("properties") : null;
      XmlTag propertyTag = properties != null ? properties.findFirstSubTag(propertyName) : null;
      if (propertyTag != null) {
        propertyTag.getValue().setText(targetVersion);
        return;
      }
      notify(
          project,
          "The version of "
              + packageName
              + " is declared via the ${"
              + propertyName
              + "} property, which is not defined in this pom. Update it in the parent or"
              + " <dependencyManagement> section.",
          NotificationType.WARNING);
      return;
    }

    // No <version> sub-tag: the version is inherited from dependencyManagement/parent. Insert an
    // explicit one so the fix is actionable instead of silently no-op-ing.
    if (versionTag == null) {
      try {
        XmlTag newVersion =
            XmlElementFactory.getInstance(project)
                .createTagFromText("<version>" + targetVersion + "</version>");
        dependencyTag.addSubTag(newVersion, false);
      } catch (IncorrectOperationException e) {
        notify(
            project,
            "Could not insert a <version> for "
                + packageName
                + ". Its version is inherited from <dependencyManagement> or a parent pom.",
            NotificationType.WARNING);
      }
      return;
    }

    // Guard against downgrading / re-applying: only write when the current literal is the
    // vulnerable
    // version and the target is strictly greater.
    if (versionText != null && !versionText.equals(currentVersion)) {
      if (VersionUtil.compareVersions(versionText, targetVersion) >= 0) {
        notify(
            project,
            packageName + " is already at version " + versionText + " (>= " + targetVersion + ").",
            NotificationType.INFORMATION);
        return;
      }
    }
    versionTag.getValue().setText(targetVersion);
  }

  private XmlTag findDependencyTag(XmlFile file, Editor editor) {
    // Prefer matching by groupId:artifactId so the fix targets the right declaration regardless of
    // caret position; fall back to the enclosing <dependency> at the caret.
    for (XmlTag tag : PsiTreeUtil.findChildrenOfType(file, XmlTag.class)) {
      if (!"dependency".equals(tag.getName())) continue;
      XmlTag group = tag.findFirstSubTag("groupId");
      XmlTag artifact = tag.findFirstSubTag("artifactId");
      if (group != null
          && artifact != null
          && packageName.equals(
              group.getValue().getTrimmedText() + ":" + artifact.getValue().getTrimmedText())) {
        return tag;
      }
    }
    if (editor == null) return null;
    PsiElement at = file.findElementAt(editor.getCaretModel().getOffset());
    XmlTag tag = PsiTreeUtil.getParentOfType(at, XmlTag.class, false);
    while (tag != null && !"dependency".equals(tag.getName())) {
      tag = tag.getParentTag();
    }
    return tag;
  }

  private void updateGradle(Project project, PsiFile file) {
    Document document = PsiDocumentManager.getInstance(project).getDocument(file);
    if (document == null) {
      return;
    }
    String oldCoordinate = packageName + ":" + currentVersion;
    String newCoordinate = packageName + ":" + targetVersion;

    String text = document.getText();
    int from = 0;
    int idx;
    boolean changed = false;
    while ((idx = text.indexOf(oldCoordinate, from)) >= 0) {
      int end = idx + oldCoordinate.length();
      boolean leftBounded = idx == 0 || !isCoordinateChar(text.charAt(idx - 1));
      boolean rightBounded = end >= text.length() || !isCoordinateChar(text.charAt(end));
      if (leftBounded && rightBounded) {
        document.replaceString(idx, end, newCoordinate);
        changed = true;
        text = document.getText();
        from = idx + newCoordinate.length();
      } else {
        from = idx + 1;
      }
    }
    PsiDocumentManager.getInstance(project).commitDocument(document);
    if (!changed) {
      notify(
          project,
          "Could not find the literal coordinate \""
              + oldCoordinate
              + "\" in "
              + file.getName()
              + ". The version may be declared via a property or version catalog; update it there"
              + " to "
              + targetVersion
              + ".",
          NotificationType.WARNING);
    }
  }

  @Override
  public boolean startInWriteAction() {
    return true;
  }
}
