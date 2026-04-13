/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.projectsapo.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.intellij.openapi.externalSystem.model.DataNode;
import com.intellij.openapi.externalSystem.model.ExternalProjectInfo;
import com.intellij.openapi.externalSystem.model.ProjectKeys;
import com.intellij.openapi.externalSystem.model.ProjectSystemId;
import com.intellij.openapi.externalSystem.model.project.LibraryData;
import com.intellij.openapi.externalSystem.model.project.ProjectData;
import com.intellij.openapi.externalSystem.service.project.ProjectDataManager;
import com.intellij.openapi.externalSystem.util.ExternalSystemApiUtil;
import com.intellij.openapi.module.Module;
import com.intellij.openapi.module.ModuleManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.roots.OrderRootType;
import com.intellij.openapi.roots.libraries.Library;
import com.intellij.openapi.roots.libraries.LibraryTable;
import com.intellij.openapi.roots.libraries.LibraryTablesRegistrar;
import com.intellij.openapi.vfs.VirtualFile;
import com.projectsapo.model.OsvPackage;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.jetbrains.idea.maven.model.MavenArtifact;
import org.jetbrains.idea.maven.model.MavenArtifactNode;
import org.jetbrains.idea.maven.project.MavenProject;
import org.jetbrains.idea.maven.project.MavenProjectsManager;
import org.jetbrains.plugins.gradle.util.GradleConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("DependencyParser Test Suite")
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class DependencyParserTest {

  @Mock private Project project;
  @Mock private MavenProjectsManager mavenProjectsManager;
  @Mock private ProjectDataManager projectDataManager;
  @Mock private ModuleManager moduleManager;
  @Mock private LibraryTablesRegistrar libraryTablesRegistrar;
  @Mock private LibraryTable libraryTable;

  private MockedStatic<MavenProjectsManager> mavenStatic;
  private MockedStatic<ProjectDataManager> projectDataStatic;
  private MockedStatic<ModuleManager> moduleManagerStatic;
  private MockedStatic<LibraryTablesRegistrar> libraryRegistrarStatic;
  private MockedStatic<ExternalSystemApiUtil> externalSystemStatic;

  @BeforeEach
  void setUp() {
    mavenStatic = mockStatic(MavenProjectsManager.class);
    projectDataStatic = mockStatic(ProjectDataManager.class);
    moduleManagerStatic = mockStatic(ModuleManager.class);
    libraryRegistrarStatic = mockStatic(LibraryTablesRegistrar.class);
    externalSystemStatic = mockStatic(ExternalSystemApiUtil.class);

    mavenStatic
        .when(() -> MavenProjectsManager.getInstance(project))
        .thenReturn(mavenProjectsManager);
    projectDataStatic.when(ProjectDataManager::getInstance).thenReturn(projectDataManager);
    moduleManagerStatic.when(() -> ModuleManager.getInstance(project)).thenReturn(moduleManager);
    libraryRegistrarStatic
        .when(LibraryTablesRegistrar::getInstance)
        .thenReturn(libraryTablesRegistrar);
  }

  @AfterEach
  void tearDown() {
    mavenStatic.close();
    projectDataStatic.close();
    moduleManagerStatic.close();
    libraryRegistrarStatic.close();
    externalSystemStatic.close();
  }

  @Nested
  @DisplayName("Maven Parsing")
  class MavenParsing {

    @Test
    @DisplayName("should_parse_maven_dependencies")
    void shouldParseMavenDependencies() {
      // Given
      MavenProject mavenProject = mock(MavenProject.class);
      when(mavenProjectsManager.hasProjects()).thenReturn(true);
      when(mavenProjectsManager.getProjects()).thenReturn(List.of(mavenProject));

      MavenArtifact artifact = mock(MavenArtifact.class);
      when(artifact.getGroupId()).thenReturn("com.example");
      when(artifact.getArtifactId()).thenReturn("lib");
      when(artifact.getVersion()).thenReturn("1.0.0");

      MavenArtifactNode node = mock(MavenArtifactNode.class);
      when(node.getArtifact()).thenReturn(artifact);
      when(node.getDependencies()).thenReturn(new ArrayList<>()); // No children

      when(mavenProject.getDependencyTree()).thenReturn(List.of(node));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project);

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("com.example:lib");
      assertThat(results.get(0).version()).isEqualTo("1.0.0");
      assertThat(results.get(0).ecosystem()).isEqualTo("Maven");
    }
  }

  @Nested
  @DisplayName("Gradle Parsing")
  class GradleParsing {

    @Test
    @DisplayName("should_parse_gradle_dependencies")
    void shouldParseGradleDependencies() {
      // Given
      when(mavenProjectsManager.hasProjects()).thenReturn(false); // Skip Maven

      ExternalProjectInfo projectInfo = mock(ExternalProjectInfo.class);
      DataNode<ProjectData> projectNode = mock(DataNode.class);
      when(projectInfo.getExternalProjectStructure()).thenReturn(projectNode);
      when(projectDataManager.getExternalProjectsData(project, GradleConstants.SYSTEM_ID))
          .thenReturn(List.of(projectInfo));

      DataNode<LibraryData> libNode = mock(DataNode.class);
      LibraryData libData = mock(LibraryData.class);
      when(libData.getGroupId()).thenReturn("com.example");
      when(libData.getArtifactId()).thenReturn("gradle-lib");
      when(libData.getVersion()).thenReturn("2.0.0");
      when(libNode.getData()).thenReturn(libData);

      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of(libNode));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project);

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("com.example:gradle-lib");
      assertThat(results.get(0).version()).isEqualTo("2.0.0");
    }
  }

  @Nested
  @DisplayName("Fallback Parsing")
  class FallbackParsing {

    @Test
    @DisplayName("should_use_fallback_when_managed_systems_empty")
    void shouldUseFallback() {
      // Given
      when(mavenProjectsManager.hasProjects()).thenReturn(false);
      when(projectDataManager.getExternalProjectsData(any(), any(ProjectSystemId.class)))
          .thenReturn(Collections.emptyList());

      when(moduleManager.getModules())
          .thenReturn(new Module[0]); // No modules to simplify order enumerator mocking
      when(libraryTablesRegistrar.getLibraryTable(project)).thenReturn(libraryTable);

      Library library = mock(Library.class);
      when(library.getName()).thenReturn("Maven: com.fallback:lib:3.0.0");
      when(libraryTable.getLibraries()).thenReturn(new Library[] {library});

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project);

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("com.fallback:lib");
      assertThat(results.get(0).version()).isEqualTo("3.0.0");
    }

    @Test
    @DisplayName("should_parse_jar_filename_correctly")
    void shouldParseJarFilename() {
      // Given
      when(mavenProjectsManager.hasProjects()).thenReturn(false);
      when(projectDataManager.getExternalProjectsData(any(), any(ProjectSystemId.class)))
          .thenReturn(Collections.emptyList());
      when(moduleManager.getModules()).thenReturn(new Module[0]);
      when(libraryTablesRegistrar.getLibraryTable(project)).thenReturn(libraryTable);

      Library library = mock(Library.class);
      when(library.getName()).thenReturn("InvalidName"); // Force file fallback
      when(library.getName()).thenReturn("InvalidName"); // Force file fallback

      VirtualFile file = mock(VirtualFile.class);
      when(file.getName()).thenReturn("commons-lang3-3.12.0.jar");
      when(file.getPath()).thenReturn("/path/to/commons-lang3-3.12.0.jar");
      when(library.getFiles(OrderRootType.CLASSES)).thenReturn(new VirtualFile[] {file});

      when(libraryTable.getLibraries()).thenReturn(new Library[] {library});

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project);

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("commons-lang3");
      assertThat(results.get(0).version()).isEqualTo("3.12.0");
    }

    @Test
    @DisplayName("should_parse_gradle_cache_path_correctly")
    void shouldParseGradleCachePath() {
      // Given
      when(mavenProjectsManager.hasProjects()).thenReturn(false);
      when(projectDataManager.getExternalProjectsData(any(), any(ProjectSystemId.class)))
          .thenReturn(Collections.emptyList());
      when(moduleManager.getModules()).thenReturn(new Module[0]);
      when(libraryTablesRegistrar.getLibraryTable(project)).thenReturn(libraryTable);

      Library library = mock(Library.class);
      when(library.getName()).thenReturn("InvalidName"); // Force file fallback

      VirtualFile file = mock(VirtualFile.class);
      when(file.getPath())
          .thenReturn(
              "/home/user/.gradle/caches/modules-2/files-2.1/com.google.guava/guava/30.1-jre/HASH/guava-30.1-jre.jar");
      when(file.getName()).thenReturn("guava-30.1-jre.jar");
      when(library.getFiles(OrderRootType.CLASSES)).thenReturn(new VirtualFile[] {file});

      when(libraryTable.getLibraries()).thenReturn(new Library[] {library});

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project);

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("com.google.guava:guava");
      assertThat(results.get(0).version()).isEqualTo("30.1-jre");
    }
  }
}
