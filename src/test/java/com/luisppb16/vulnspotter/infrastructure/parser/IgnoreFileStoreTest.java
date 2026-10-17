/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.parser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.intellij.openapi.project.Project;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("IgnoreFileStore Test Suite")
class IgnoreFileStoreTest {

  @Mock private Project project;

  @TempDir private Path tempDir;

  private String writeIgnoreFile(String content) throws IOException {
    Path ignoreFile = tempDir.resolve(IgnoreFileStore.FILE_NAME);
    Files.writeString(ignoreFile, content);
    return ignoreFile.toString();
  }

  @Test
  @DisplayName("should_return_empty_when_file_does_not_exist")
  void shouldReturnEmptyWhenFileDoesNotExist() {
    // Given
    when(project.getBasePath()).thenReturn(tempDir.toString());

    // When
    Set<String> patterns = IgnoreFileStore.readPatterns(project);

    // Then
    assertThat(patterns).isEmpty();
  }

  @Test
  @DisplayName("should_return_null_path_when_project_has_no_base_path")
  void shouldReturnNullPathWhenProjectHasNoBasePath() {
    // Given
    when(project.getBasePath()).thenReturn(null);

    // When / Then
    assertThat(IgnoreFileStore.ignoreFilePath(project)).isNull();
    assertThat(IgnoreFileStore.readPatterns(project)).isEmpty();
  }

  @Test
  @DisplayName("should_skip_comments_and_blank_lines_and_keep_patterns_case_preserved")
  void shouldSkipCommentsAndBlankLines() throws IOException {
    // Given
    writeIgnoreFile(
        "# a comment\n"
            + "\n"
            + "  \n"
            + "com.example:lib\n"
            + "  com.other:*  \n"
            + "Maven:com.example:lib@1.0.0\n");

    // When
    Set<String> patterns;
    when(project.getBasePath()).thenReturn(tempDir.toString());
    patterns = IgnoreFileStore.readPatterns(project);

    // Then
    assertThat(patterns)
        .containsExactlyInAnyOrder("com.example:lib", "com.other:*", "Maven:com.example:lib@1.0.0");
    // Case preserved verbatim (matching case rules belong to the parser, not the store).
    assertThat(patterns).contains("Maven:com.example:lib@1.0.0");
  }

  @Test
  @DisplayName("should_return_empty_when_file_is_unreadable")
  void shouldReturnEmptyWhenFileIsUnreadable() throws IOException {
    // Given: a directory named as the ignore file makes readAllLines fail — reading must degrade
    // to "no rules", never fail the scan.
    Files.createDirectory(tempDir.resolve(IgnoreFileStore.FILE_NAME));

    // When
    when(project.getBasePath()).thenReturn(tempDir.toString());
    Set<String> patterns = IgnoreFileStore.readPatterns(project);

    // Then
    assertThat(patterns).isEmpty();
  }

  @Test
  @DisplayName("should_append_entry_creating_the_file_when_absent")
  void shouldAppendEntryCreatingTheFileWhenAbsent() throws IOException {
    // Given
    when(project.getBasePath()).thenReturn(tempDir.toString());

    // When
    IgnoreFileStore.appendEntry(project, "com.example:lib");
    IgnoreFileStore.appendEntry(project, "com.example:other");

    // Then
    Path ignoreFile = tempDir.resolve(IgnoreFileStore.FILE_NAME);
    assertThat(Files.readAllLines(ignoreFile))
        .containsExactly("com.example:lib", "com.example:other");
  }

  @Test
  @DisplayName("should_throw_when_project_has_no_base_path")
  void shouldThrowWhenProjectHasNoBasePath() {
    // Given
    when(project.getBasePath()).thenReturn(null);

    // When / Then: fail-fast so the caller's error path notifies instead of silently succeeding.
    org.junit.jupiter.api.Assertions.assertThrows(
        IOException.class, () -> IgnoreFileStore.appendEntry(project, "com.example:lib"));
  }

  @Test
  @DisplayName("should_round_trip_written_entry_through_the_parser")
  void shouldRoundTripWrittenEntryThroughTheParser() throws IOException {
    // Given: an entry written by the store is matched by the parser (broad bare-name behavior).
    when(project.getBasePath()).thenReturn(tempDir.toString());
    IgnoreFileStore.appendEntry(project, "com.example:lib");

    // When
    Set<String> patterns = IgnoreFileStore.readPatterns(project);

    // Then
    assertThat(
            VulnSpotterIgnoreParser.isIgnored(
                patterns, new OsvPackage("com.example:lib", "Maven", "9.9.9")))
        .isTrue();
    // npm matching is case-insensitive; write the npm-ecosystem rule with mixed case as users do.
    assertThat(
            VulnSpotterIgnoreParser.isIgnored(
                Set.of("React"), new OsvPackage("react", "npm", "18.0.0")))
        .isTrue();
  }
}
