/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.parser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.intellij.openapi.externalSystem.model.DataNode;
import com.intellij.openapi.externalSystem.model.ExternalProjectInfo;
import com.intellij.openapi.externalSystem.model.ProjectKeys;
import com.intellij.openapi.externalSystem.model.ProjectSystemId;
import com.intellij.openapi.externalSystem.model.project.LibraryData;
import com.intellij.openapi.externalSystem.model.project.LibraryDependencyData;
import com.intellij.openapi.externalSystem.model.project.ModuleData;
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
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.jetbrains.idea.maven.model.MavenArtifact;
import org.jetbrains.idea.maven.model.MavenArtifactNode;
import org.jetbrains.idea.maven.model.MavenArtifactState;
import org.jetbrains.idea.maven.project.MavenProject;
import org.jetbrains.idea.maven.project.MavenProjectsManager;
import org.jetbrains.plugins.gradle.util.GradleConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@DisplayName("DependencyParser Test Suite")
@MockitoSettings(strictness = Strictness.LENIENT)
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
      when(node.getState()).thenReturn(MavenArtifactState.ADDED);
      when(node.getArtifact()).thenReturn(artifact);
      when(node.getDependencies()).thenReturn(new ArrayList<>()); // No children

      when(mavenProject.getDependencyTree()).thenReturn(List.of(node));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("com.example:lib");
      assertThat(results.get(0).version()).isEqualTo("1.0.0");
      assertThat(results.get(0).ecosystem()).isEqualTo("Maven");
    }

    @Test
    @DisplayName("should_skip_an_added_node_with_a_null_artifact_instead_of_failing")
    void shouldSkipAnAddedNodeWithANullArtifactInsteadOfFailing() {
      // Given: a stale or partially resolved model can present an ADDED node without its
      // artifact — the walks must skip it instead of an NPE losing the whole pass.
      MavenArtifactNode fineNode = addedNode("com.example", "fine", "3.0.0", List.of());
      MavenArtifactNode brokenNode = mock(MavenArtifactNode.class);
      when(brokenNode.getState()).thenReturn(MavenArtifactState.ADDED);
      // brokenNode.getArtifact() stays the mock default: null.
      when(brokenNode.getDependencies()).thenReturn(List.of(fineNode));

      when(mavenProjectsManager.hasProjects()).thenReturn(true);
      MavenProject mavenProject = mock(MavenProject.class);
      when(mavenProjectsManager.getProjects()).thenReturn(List.of(mavenProject));
      when(mavenProject.getDependencyTree()).thenReturn(List.of(brokenNode));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: the malformed node is skipped; its reachable children still make it into the scan.
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("com.example:fine");
    }

    @ParameterizedTest
    @EnumSource(value = MavenArtifactState.class, mode = EnumSource.Mode.EXCLUDE, names = "ADDED")
    @DisplayName("should_prune_mediated_nodes_with_their_subtree")
    void shouldPruneMediatedNodesWithTheirSubtree(MavenArtifactState lostState) {
      // Given: this path lost the conflict/duplicate mediation between dependency paths — a common
      // outcome in multi-module projects, e.g. when a parent POM manages the version and a nearer
      // path wins with another one. Only fully-ADDED paths are on the effective classpath, so the
      // loser and its subtree must never reach OSV.
      MavenArtifact lostArtifact = mock(MavenArtifact.class);
      when(lostArtifact.getGroupId()).thenReturn("com.example");
      when(lostArtifact.getArtifactId()).thenReturn("loser");
      when(lostArtifact.getVersion()).thenReturn("1.0.0");

      MavenArtifactNode loserNode = mock(MavenArtifactNode.class);
      when(loserNode.getState()).thenReturn(lostState);
      when(loserNode.getArtifact()).thenReturn(lostArtifact);
      MavenArtifactNode ghostNode = addedNode("com.example", "ghost", "9.9.9", List.of());
      when(loserNode.getDependencies()).thenReturn(List.of(ghostNode)); // must never be traversed

      MavenArtifactNode siblingNode = addedNode("com.example", "real", "2.0.0", List.of());
      MavenArtifactNode rootNode =
          addedNode("com.example", "root", "1.0.0", List.of(loserNode, siblingNode));

      when(mavenProjectsManager.hasProjects()).thenReturn(true);
      MavenProject mavenProject = mock(MavenProject.class);
      when(mavenProjectsManager.getProjects()).thenReturn(List.of(mavenProject));
      when(mavenProject.getDependencyTree()).thenReturn(List.of(rootNode));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results)
          .extracting(OsvPackage::name)
          .containsExactlyInAnyOrder("com.example:real", "com.example:root");
      verify(loserNode, never()).getDependencies();
    }

    @Test
    @DisplayName("should_collect_all_dependencies_in_a_fully_added_tree")
    void shouldCollectAllDependenciesInFullyAddedTree() {
      // Given
      MavenArtifactNode grandchildNode = addedNode("com.example", "grandchild", "3.0.0", List.of());
      MavenArtifactNode childNode =
          addedNode("com.example", "child", "2.0.0", List.of(grandchildNode));
      MavenArtifactNode rootNode = addedNode("com.example", "root", "1.0.0", List.of(childNode));

      when(mavenProjectsManager.hasProjects()).thenReturn(true);
      MavenProject mavenProject = mock(MavenProject.class);
      when(mavenProjectsManager.getProjects()).thenReturn(List.of(mavenProject));
      when(mavenProject.getDependencyTree()).thenReturn(List.of(rootNode));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results)
          .extracting(OsvPackage::name)
          .containsExactly("com.example:child", "com.example:grandchild", "com.example:root");
      assertThat(results.get(1).dependencyChains())
          .containsExactly(
              List.of("com.example:root", "com.example:child", "com.example:grandchild"));
    }

    @Test
    @DisplayName("should_publish_resolved_version_index_while_walking_the_tree")
    void shouldPublishResolvedVersionIndexWhileWalkingTheTree() {
      // Given: a pom declaring the same coordinate through two paths; the pre-order DFS visits
      // the first ADDED occurrence first, and the index must keep that one (first-wins, exactly
      // like findResolvedVersion).
      MavenProject mavenProject = mock(MavenProject.class);
      VirtualFile pom = mock(VirtualFile.class);
      when(mavenProject.getFile()).thenReturn(pom);
      MavenArtifactNode firstPathNode = addedNode("com.example", "lib", "1.2.3", List.of());
      MavenArtifactNode secondPathNode = addedNode("com.example", "lib", "4.5.6", List.of());
      MavenArtifactNode rootNode =
          addedNode("com.example", "root", "1.0.0", List.of(firstPathNode, secondPathNode));

      when(mavenProjectsManager.hasProjects()).thenReturn(true);
      when(mavenProjectsManager.getProjects()).thenReturn(List.of(mavenProject));
      when(mavenProject.getDependencyTree()).thenReturn(List.of(rootNode));

      // When
      DependencyParser.ParseOutcome outcome = DependencyParser.parseDependencies(project);

      // Then
      assertThat(outcome.resolvedVersions().get(pom)).containsEntry("com.example:lib", "1.2.3");
      assertThat(outcome.packages()).extracting(OsvPackage::name).contains("com.example:lib");
    }

    @Test
    @DisplayName("should_skip_artifact_without_version_and_keep_parsing_tree")
    void shouldSkipArtifactWithoutVersionAndKeepParsingTree() {
      // Given: a null version would make OsvPackage throw an NPE, aborting the whole Maven parse.
      MavenArtifact brokenArtifact = mock(MavenArtifact.class);
      when(brokenArtifact.getGroupId()).thenReturn("com.example");
      when(brokenArtifact.getArtifactId()).thenReturn("no-version");
      when(brokenArtifact.getVersion()).thenReturn(null);

      MavenArtifactNode brokenNode = mock(MavenArtifactNode.class);
      when(brokenNode.getState()).thenReturn(MavenArtifactState.ADDED);
      when(brokenNode.getArtifact()).thenReturn(brokenArtifact);
      MavenArtifactNode childNode = addedNode("com.example", "child", "2.0.0", List.of());
      when(brokenNode.getDependencies()).thenReturn(List.of(childNode));

      when(mavenProjectsManager.hasProjects()).thenReturn(true);
      MavenProject mavenProject = mock(MavenProject.class);
      when(mavenProjectsManager.getProjects()).thenReturn(List.of(mavenProject));
      MavenArtifactNode healthyNode = addedNode("com.example", "healthy", "3.0.0", List.of());
      when(mavenProject.getDependencyTree()).thenReturn(List.of(brokenNode, healthyNode));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results)
          .extracting(OsvPackage::name)
          .containsExactlyInAnyOrder("com.example:child", "com.example:healthy");
    }

    private MavenArtifactNode addedNode(
        String groupId, String artifactId, String version, List<MavenArtifactNode> children) {
      MavenArtifact artifact = mock(MavenArtifact.class);
      when(artifact.getGroupId()).thenReturn(groupId);
      when(artifact.getArtifactId()).thenReturn(artifactId);
      when(artifact.getVersion()).thenReturn(version);

      MavenArtifactNode node = mock(MavenArtifactNode.class);
      when(node.getState()).thenReturn(MavenArtifactState.ADDED);
      when(node.getArtifact()).thenReturn(artifact);
      when(node.getDependencies()).thenReturn(children);
      return node;
    }
  }

  @Nested
  @DisplayName("Maven Resolved Version")
  class MavenResolvedVersion {

    @Test
    @DisplayName("should_return_effective_version_of_added_node")
    void shouldReturnEffectiveVersionOfAddedNode() {
      // Given: what the scan queried OSV with for a ${...} version must be recoverable from the
      // pom's resolved tree.
      VirtualFile pomFile = mock(VirtualFile.class);
      MavenProject mavenProject = mock(MavenProject.class);
      when(mavenProjectsManager.findProject(pomFile)).thenReturn(mavenProject);
      MavenArtifactNode childNode = addedNode("com.example", "lib", "1.2.3", List.of());
      MavenArtifactNode rootNode = addedNode("com.example", "root", "1.0.0", List.of(childNode));
      when(mavenProject.getDependencyTree()).thenReturn(List.of(rootNode));

      // When
      String version = DependencyParser.findResolvedVersion(project, pomFile, "com.example", "lib");

      // Then
      assertThat(version).isEqualTo("1.2.3");
    }

    @ParameterizedTest
    @EnumSource(value = MavenArtifactState.class, mode = EnumSource.Mode.EXCLUDE, names = "ADDED")
    @DisplayName("should_return_null_when_only_lost_nodes_match")
    void shouldReturnNullWhenOnlyLostNodesMatch(MavenArtifactState lostState) {
      // Given: the coordinate is only reachable through a mediated-away node, whose subtree is
      // pruned — the scan never asked OSV about it, so there is nothing to match against.
      MavenArtifact lostArtifact = mock(MavenArtifact.class);
      when(lostArtifact.getGroupId()).thenReturn("com.example");
      when(lostArtifact.getArtifactId()).thenReturn("lib");
      when(lostArtifact.getVersion()).thenReturn("1.0.0");

      MavenArtifactNode lostNode = mock(MavenArtifactNode.class);
      when(lostNode.getState()).thenReturn(lostState);
      when(lostNode.getArtifact()).thenReturn(lostArtifact);
      MavenArtifactNode ghostNode = addedNode("com.example", "ghost", "9.9.9", List.of());
      when(lostNode.getDependencies()).thenReturn(List.of(ghostNode)); // must never be traversed

      VirtualFile pomFile = mock(VirtualFile.class);
      MavenProject mavenProject = mock(MavenProject.class);
      when(mavenProjectsManager.findProject(pomFile)).thenReturn(mavenProject);
      when(mavenProject.getDependencyTree()).thenReturn(List.of(lostNode));

      // When
      String version = DependencyParser.findResolvedVersion(project, pomFile, "com.example", "lib");

      // Then
      assertThat(version).isNull();
      verify(lostNode, never()).getDependencies();
    }

    @Test
    @DisplayName("should_return_null_when_pom_is_not_registered")
    void shouldReturnNullWhenPomIsNotRegistered() {
      // Given
      VirtualFile pomFile = mock(VirtualFile.class);
      when(mavenProjectsManager.findProject(pomFile)).thenReturn(null);

      // When
      String version = DependencyParser.findResolvedVersion(project, pomFile, "com.example", "lib");

      // Then
      assertThat(version).isNull();
    }

    @Test
    @DisplayName("should_return_null_when_coordinate_is_not_in_the_tree")
    void shouldReturnNullWhenCoordinateIsNotInTheTree() {
      // Given
      VirtualFile pomFile = mock(VirtualFile.class);
      MavenProject mavenProject = mock(MavenProject.class);
      when(mavenProjectsManager.findProject(pomFile)).thenReturn(mavenProject);
      MavenArtifactNode rootNode = addedNode("com.example", "other", "1.0.0", List.of());
      when(mavenProject.getDependencyTree()).thenReturn(List.of(rootNode));

      // When
      String version = DependencyParser.findResolvedVersion(project, pomFile, "com.example", "lib");

      // Then
      assertThat(version).isNull();
    }

    @Test
    @DisplayName("should_return_null_when_no_pom_file_is_given")
    void shouldReturnNullWhenNoPomFileIsGiven() {
      // When
      String version = DependencyParser.findResolvedVersion(project, null, "com.example", "lib");

      // Then
      assertThat(version).isNull();
    }

    @Test
    @DisplayName("should_return_null_when_projects_manager_is_missing")
    void shouldReturnNullWhenProjectsManagerIsMissing() {
      // Given
      mavenStatic.when(() -> MavenProjectsManager.getInstance(project)).thenReturn(null);

      // When
      String version =
          DependencyParser.findResolvedVersion(
              project, mock(VirtualFile.class), "com.example", "lib");

      // Then
      assertThat(version).isNull();
    }

    private MavenArtifactNode addedNode(
        String groupId, String artifactId, String version, List<MavenArtifactNode> children) {
      MavenArtifact artifact = mock(MavenArtifact.class);
      when(artifact.getGroupId()).thenReturn(groupId);
      when(artifact.getArtifactId()).thenReturn(artifactId);
      when(artifact.getVersion()).thenReturn(version);

      MavenArtifactNode node = mock(MavenArtifactNode.class);
      when(node.getState()).thenReturn(MavenArtifactState.ADDED);
      when(node.getArtifact()).thenReturn(artifact);
      when(node.getDependencies()).thenReturn(children);
      return node;
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
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.MODULE)))
          .thenReturn(List.of());

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("com.example:gradle-lib");
      assertThat(results.get(0).version()).isEqualTo("2.0.0");
    }

    @Test
    @DisplayName("should_attach_gradle_dependency_chains_for_provenance")
    void shouldAttachGradleDependencyChainsForProvenance() {
      // Given: a module whose dependency tree nests the Jackson core under the platform
      // test framework, the real shape that pulls tools.jackson.core into the classpath.
      when(mavenProjectsManager.hasProjects()).thenReturn(false); // Skip Maven

      ExternalProjectInfo projectInfo = mock(ExternalProjectInfo.class);
      DataNode<ProjectData> projectNode = mock(DataNode.class);
      when(projectInfo.getExternalProjectStructure()).thenReturn(projectNode);
      when(projectDataManager.getExternalProjectsData(project, GradleConstants.SYSTEM_ID))
          .thenReturn(List.of(projectInfo));

      DataNode<ModuleData> moduleNode = mock(DataNode.class);
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.MODULE)))
          .thenReturn(List.of(moduleNode));

      DataNode<LibraryData> jacksonLibNode = mock(DataNode.class);
      LibraryData jacksonLibRoot = mock(LibraryData.class);
      when(jacksonLibRoot.getGroupId()).thenReturn("tools.jackson.core");
      when(jacksonLibRoot.getArtifactId()).thenReturn("jackson-core");
      when(jacksonLibRoot.getVersion()).thenReturn("3.1.4");
      when(jacksonLibNode.getData()).thenReturn(jacksonLibRoot);
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of());
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(moduleNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of(jacksonLibNode));

      DataNode<LibraryDependencyData> frameworkDep = mock(DataNode.class);
      LibraryDependencyData frameworkDepData = mock(LibraryDependencyData.class);
      LibraryData frameworkLib = mock(LibraryData.class);
      when(frameworkDep.getData()).thenReturn(frameworkDepData);
      when(frameworkDepData.getTarget()).thenReturn(frameworkLib);
      when(frameworkLib.getGroupId()).thenReturn("com.jetbrains.intellij.platform");
      when(frameworkLib.getArtifactId()).thenReturn("test-framework-core");

      DataNode<LibraryDependencyData> jacksonDep = mock(DataNode.class);
      LibraryDependencyData jacksonDepData = mock(LibraryDependencyData.class);
      LibraryData jacksonLib = mock(LibraryData.class);
      when(jacksonDep.getData()).thenReturn(jacksonDepData);
      when(jacksonDepData.getTarget()).thenReturn(jacksonLib);
      when(jacksonLib.getGroupId()).thenReturn("tools.jackson.core");
      when(jacksonLib.getArtifactId()).thenReturn("jackson-core");

      externalSystemStatic
          .when(
              () ->
                  ExternalSystemApiUtil.getChildren(
                      eq(moduleNode), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(frameworkDep));
      externalSystemStatic
          .when(
              () ->
                  ExternalSystemApiUtil.getChildren(
                      eq(frameworkDep), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(jacksonDep));
      externalSystemStatic
          .when(
              () ->
                  ExternalSystemApiUtil.getChildren(
                      eq(jacksonDep), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of());

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: the nested coordinate carries the chain that pulls it in.
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("tools.jackson.core:jackson-core");
      assertThat(results.get(0).version()).isEqualTo("3.1.4");
      assertThat(results.get(0).dependencyChains())
          .containsExactly(
              List.of(
                  "com.jetbrains.intellij.platform:test-framework-core",
                  "tools.jackson.core:jackson-core"));
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
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("com.fallback:lib");
      assertThat(results.get(0).version()).isEqualTo("3.0.0");
    }

    @Test
    @DisplayName("should_skip_jar_filename_without_maven_coordinates")
    void shouldSkipJarFilenameWithoutMavenCoordinates() {
      // Given: a bare jar filename yields only the artifactId, but OSV's Maven ecosystem requires
      // "group:artifact" — querying with just the artifact name is a silent false negative, so the
      // parser must skip it instead of emitting a package.
      when(mavenProjectsManager.hasProjects()).thenReturn(false);
      when(projectDataManager.getExternalProjectsData(any(), any(ProjectSystemId.class)))
          .thenReturn(Collections.emptyList());
      when(moduleManager.getModules()).thenReturn(new Module[0]);
      when(libraryTablesRegistrar.getLibraryTable(project)).thenReturn(libraryTable);

      Library library = mock(Library.class);
      when(library.getName()).thenReturn("InvalidName"); // Force file fallback

      VirtualFile file = mock(VirtualFile.class);
      when(file.getName()).thenReturn("commons-lang3-3.12.0.jar");
      when(file.getPath()).thenReturn("/path/to/commons-lang3-3.12.0.jar");
      when(library.getFiles(OrderRootType.CLASSES)).thenReturn(new VirtualFile[] {file});

      when(libraryTable.getLibraries()).thenReturn(new Library[] {library});

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).isEmpty();
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
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).name()).isEqualTo("com.google.guava:guava");
      assertThat(results.get(0).version()).isEqualTo("30.1-jre");
    }
  }
}
