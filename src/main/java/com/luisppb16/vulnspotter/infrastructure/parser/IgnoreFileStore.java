/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.parser;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Owns the {@code .vulnspotterignore} file: its location and its raw line format (one pattern per
 * line, {@code #} comments, blanks ignored). {@link VulnSpotterIgnoreParser} owns the matching
 * semantics of those patterns.
 *
 * <p>Reading degrades open: an unreadable or missing file means "no ignore rules", never a scan
 * failure.
 */
public final class IgnoreFileStore {

  public static final String FILE_NAME = ".vulnspotterignore";
  private static final Logger LOG = Logger.getInstance(IgnoreFileStore.class);

  private IgnoreFileStore() {
    throw new UnsupportedOperationException("Utility class");
  }

  /** Project-relative ignore-file path, or {@code null} when the project has no base path. */
  public static Path ignoreFilePath(Project project) {
    String basePath = project.getBasePath();
    return basePath == null ? null : Paths.get(basePath, FILE_NAME);
  }

  /** Case-preserved pattern set (comments and blanks dropped); empty when the file is missing. */
  public static Set<String> readPatterns(Project project) {
    Path ignoreFilePath = ignoreFilePath(project);
    if (ignoreFilePath == null || !Files.exists(ignoreFilePath)) {
      return Set.of();
    }

    try {
      return Files.readAllLines(ignoreFilePath).stream()
          .map(String::trim)
          .filter(line -> !line.isEmpty() && !line.startsWith("#"))
          .collect(Collectors.toUnmodifiableSet());
    } catch (IOException e) {
      LOG.warn("Failed to read .vulnspotterignore; ignore rules are not being applied", e);
      return Set.of();
    }
  }

  /**
   * Appends one pattern line, creating the file when absent. The entry is written verbatim; the
   * bare package name keeps today's broad "ignore every version of this name" behavior.
   *
   * @throws IOException so the caller can surface a real error instead of failing silently.
   */
  public static void appendEntry(Project project, String entry) throws IOException {
    Path ignoreFilePath = ignoreFilePath(project);
    if (ignoreFilePath == null) {
      throw new IOException("The project has no base path: cannot write .vulnspotterignore");
    }
    Files.writeString(
        ignoreFilePath,
        entry + System.lineSeparator(),
        StandardOpenOption.CREATE,
        StandardOpenOption.APPEND);
  }
}
