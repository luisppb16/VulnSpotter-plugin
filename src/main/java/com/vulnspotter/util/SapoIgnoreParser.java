/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.vulnspotter.util;

import com.intellij.openapi.project.Project;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class SapoIgnoreParser {

  private SapoIgnoreParser() {}

  public static Set<String> getIgnoredDependencies(Project project) {
    if (project.getBasePath() == null) {
      return Collections.emptySet();
    }

    Path ignoreFilePath = Paths.get(project.getBasePath(), ".sapoignore");
    if (!Files.exists(ignoreFilePath)) {
      return Collections.emptySet();
    }

    try {
      List<String> lines = Files.readAllLines(ignoreFilePath);
      Set<String> ignored = new HashSet<>();
      for (String line : lines) {
        String trimmed = line.trim();
        if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
          // Store just the name, or ecosystem:name if provided. We simplify to just names for exact
          // matches.
          ignored.add(trimmed);
        }
      }
      return ignored;
    } catch (IOException e) {
      return Collections.emptySet();
    }
  }
}
