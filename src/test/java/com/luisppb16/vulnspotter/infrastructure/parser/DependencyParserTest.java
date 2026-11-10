/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.parser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
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
import com.intellij.openapi.externalSystem.model.project.LibraryPathType;
import com.intellij.openapi.externalSystem.model.project.ModuleData;
import com.intellij.openapi.externalSystem.model.project.ProjectData;
import com.intellij.openapi.externalSystem.service.project.ProjectDataManager;
import com.intellij.openapi.externalSystem.util.ExternalSystemApiUtil;
import com.intellij.openapi.module.Module;
import com.intellij.openapi.module.ModuleManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.roots.DependencyScope;
import com.intellij.openapi.roots.OrderRootType;
import com.intellij.openapi.roots.libraries.Library;
import com.intellij.openapi.roots.libraries.LibraryTable;
import com.intellij.openapi.roots.libraries.LibraryTablesRegistrar;
import com.intellij.openapi.vfs.VirtualFile;
import com.luisppb16.vulnspotter.domain.model.DependencyProvenance;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jetbrains.idea.maven.model.MavenArtifact;
import org.jetbrains.idea.maven.model.MavenArtifactNode;
import org.jetbrains.idea.maven.model.MavenArtifactState;
import org.jetbrains.idea.maven.project.MavenProject;
import org.jetbrains.idea.maven.project.MavenProjectsManager;
import org.jetbrains.plugins.gradle.model.ExternalDependency;
import org.jetbrains.plugins.gradle.model.ExternalProject;
import org.jetbrains.plugins.gradle.model.ExternalProjectDependency;
import org.jetbrains.plugins.gradle.model.ExternalSourceSet;
import org.jetbrains.plugins.gradle.model.FileCollectionDependency;
import org.jetbrains.plugins.gradle.service.project.data.ExternalProjectDataCache;
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
  @Mock private ExternalProjectDataCache externalProjectDataCache;

  private MockedStatic<MavenProjectsManager> mavenStatic;
  private MockedStatic<ProjectDataManager> projectDataStatic;
  private MockedStatic<ModuleManager> moduleManagerStatic;
  private MockedStatic<LibraryTablesRegistrar> libraryRegistrarStatic;
  private MockedStatic<ExternalSystemApiUtil> externalSystemStatic;
  private MockedStatic<ExternalProjectDataCache> externalProjectCacheStatic;

  @BeforeEach
  void setUp() {
    mavenStatic = mockStatic(MavenProjectsManager.class);
    projectDataStatic = mockStatic(ProjectDataManager.class);
    moduleManagerStatic = mockStatic(ModuleManager.class);
    libraryRegistrarStatic = mockStatic(LibraryTablesRegistrar.class);
    externalSystemStatic = mockStatic(ExternalSystemApiUtil.class);
    externalProjectCacheStatic = mockStatic(ExternalProjectDataCache.class);

    mavenStatic
        .when(() -> MavenProjectsManager.getInstance(project))
        .thenReturn(mavenProjectsManager);
    projectDataStatic.when(ProjectDataManager::getInstance).thenReturn(projectDataManager);
    moduleManagerStatic.when(() -> ModuleManager.getInstance(project)).thenReturn(moduleManager);
    libraryRegistrarStatic
        .when(LibraryTablesRegistrar::getInstance)
        .thenReturn(libraryTablesRegistrar);
    externalProjectCacheStatic
        .when(() -> ExternalProjectDataCache.getInstance(project))
        .thenReturn(externalProjectDataCache);
  }

  @AfterEach
  void tearDown() {
    mavenStatic.close();
    projectDataStatic.close();
    moduleManagerStatic.close();
    libraryRegistrarStatic.close();
    externalSystemStatic.close();
    externalProjectCacheStatic.close();
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

    /** Library data mock under the given group/artifact/version coordinates. */
    private static LibraryData libraryData(String group, String artifact, String version) {
      LibraryData data = mock(LibraryData.class);
      when(data.getGroupId()).thenReturn(group);
      when(data.getArtifactId()).thenReturn(artifact);
      when(data.getVersion()).thenReturn(version);
      return data;
    }

    /** Library node mock carrying the given library data. */
    private static DataNode<LibraryData> libraryNode(LibraryData data) {
      DataNode<LibraryData> libNode = mock(DataNode.class);
      when(libNode.getData()).thenReturn(data);
      return libNode;
    }

    /** Edge node mock whose target library carries the given coordinates. */
    private static DataNode<LibraryDependencyData> stubEdgeNode(
        String group, String artifact, String version) {
      return stubEdgeNode(group, artifact, version, null);
    }

    /** Edge node mock with the given coordinates and dependency scope (null keeps the default). */
    private static DataNode<LibraryDependencyData> stubEdgeNode(
        String group, String artifact, String version, DependencyScope scope) {
      LibraryData target = libraryData(group, artifact, version);
      LibraryDependencyData data = mock(LibraryDependencyData.class);
      when(data.getTarget()).thenReturn(target);
      if (scope != null) {
        when(data.getScope()).thenReturn(scope);
      }
      DataNode<LibraryDependencyData> dependency = mock(DataNode.class);
      when(dependency.getData()).thenReturn(data);
      return dependency;
    }

    /** Edge node mock targeting the given library data directly (no coordinate stubs needed). */
    private static DataNode<LibraryDependencyData> stubEdgeNode(LibraryData target) {
      LibraryDependencyData data = mock(LibraryDependencyData.class);
      when(data.getTarget()).thenReturn(target);
      DataNode<LibraryDependencyData> dependency = mock(DataNode.class);
      when(dependency.getData()).thenReturn(data);
      return dependency;
    }

    /** ExternalProject mock carrying the source sets the parser walks. */
    private static ExternalProject externalProject(
        Map<String, ? extends ExternalSourceSet> sourceSets) {
      ExternalProject project = mock(ExternalProject.class);
      doReturn(sourceSets).when(project).getSourceSets();
      return project;
    }

    private static ExternalSourceSet externalSourceSet(
        String name, ExternalDependency... dependencies) {
      ExternalSourceSet sourceSet = mock(ExternalSourceSet.class);
      when(sourceSet.getName()).thenReturn(name);
      doReturn(List.of(dependencies)).when(sourceSet).getDependencies();
      return sourceSet;
    }

    private static ExternalDependency externalLibraryDependency(
        String group,
        String name,
        String version,
        String scope,
        List<ExternalDependency> children) {
      ExternalDependency dependency = mock(ExternalDependency.class);
      when(dependency.getGroup()).thenReturn(group);
      when(dependency.getName()).thenReturn(name);
      when(dependency.getVersion()).thenReturn(version);
      when(dependency.getScope()).thenReturn(scope);
      doReturn(children).when(dependency).getDependencies();
      return dependency;
    }

    private static ExternalDependency fileCollectionDependency(List<ExternalDependency> children) {
      ExternalDependency dependency = mock(FileCollectionDependency.class);
      when(dependency.getGroup()).thenReturn(null);
      when(dependency.getName()).thenReturn(null);
      when(dependency.getVersion()).thenReturn(null);
      when(dependency.getScope()).thenReturn(null);
      doReturn(children).when(dependency).getDependencies();
      return dependency;
    }

    private static ExternalDependency projectDependency(
        String projectPath, List<ExternalDependency> children) {
      ExternalDependency dependency = mock(ExternalProjectDependency.class);
      when(dependency.getGroup()).thenReturn(null);
      when(dependency.getName()).thenReturn(null);
      when(dependency.getVersion()).thenReturn(null);
      when(dependency.getScope()).thenReturn(null);
      doReturn(children).when(dependency).getDependencies();
      return dependency;
    }

    /** {@code dependencyChains} of the scanned package with the given version. */
    private static Set<List<String>> chainsOf(List<OsvPackage> results, String version) {
      return results.stream()
          .filter(result -> result.version().equals(version))
          .findFirst()
          .orElseThrow()
          .dependencyChains();
    }

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
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(moduleNode), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(frameworkDep));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(
                  eq(frameworkDep), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(jacksonDep));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(jacksonDep), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
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

    @Test
    @DisplayName("should_key_gradle_chains_by_version_to_keep_configurations_separate")
    void shouldKeyGradleChainsByVersionToKeepConfigurationsSeparate() {
      // Given: one coordinate resolved to two versions, each pulled by its own direct dependency
      // in its own module, exactly what two configurations with the same library produce.
      when(mavenProjectsManager.hasProjects()).thenReturn(false);

      ExternalProjectInfo projectInfo = mock(ExternalProjectInfo.class);
      DataNode<ProjectData> projectNode = mock(DataNode.class);
      when(projectInfo.getExternalProjectStructure()).thenReturn(projectNode);
      when(projectDataManager.getExternalProjectsData(project, GradleConstants.SYSTEM_ID))
          .thenReturn(List.of(projectInfo));

      DataNode<ModuleData> firstModule = mock(DataNode.class);
      DataNode<ModuleData> secondModule = mock(DataNode.class);
      DataNode<LibraryData> firstSharedLib = libraryNode(libraryData("g", "a", "1.0.0"));
      DataNode<LibraryData> secondSharedLib = libraryNode(libraryData("g", "a", "2.0.0"));
      DataNode<LibraryDependencyData> firstDirect = stubEdgeNode("d", "direct", "0.5.0");
      DataNode<LibraryDependencyData> firstShared = stubEdgeNode("g", "a", "1.0.0");
      DataNode<LibraryDependencyData> secondDirect = stubEdgeNode("o", "other", "1.5.0");
      DataNode<LibraryDependencyData> secondShared = stubEdgeNode("g", "a", "2.0.0");

      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.MODULE)))
          .thenReturn(List.of(firstModule, secondModule));
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of());
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(firstModule), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of(firstSharedLib));
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(secondModule), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of(secondSharedLib));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(
                  eq(firstModule), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(firstDirect));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(
                  eq(firstDirect), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(firstShared));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(
                  eq(firstShared), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of());
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(
                  eq(secondModule), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(secondDirect));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(
                  eq(secondDirect), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(secondShared));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(
                  eq(secondShared), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of());

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: each version received only the chains that actually pull it in.
      assertThat(results).hasSize(2);
      assertThat(chainsOf(results, "1.0.0")).containsExactly(List.of("d:direct", "g:a"));
      assertThat(chainsOf(results, "2.0.0")).containsExactly(List.of("o:other", "g:a"));
    }

    @Test
    @DisplayName("should_recover_the_coordinate_from_the_binary_path_when_the_target_lacks_it")
    void shouldRecoverTheCoordinateFromTheBinaryPathWhenTheTargetLacksIt() {
      // Given: a merged multi-artifact target without group/artifact whose jar survives in the
      // Gradle cache under the real group/artifact/version.
      when(mavenProjectsManager.hasProjects()).thenReturn(false);

      ExternalProjectInfo projectInfo = mock(ExternalProjectInfo.class);
      DataNode<ProjectData> projectNode = mock(DataNode.class);
      when(projectInfo.getExternalProjectStructure()).thenReturn(projectNode);
      when(projectDataManager.getExternalProjectsData(project, GradleConstants.SYSTEM_ID))
          .thenReturn(List.of(projectInfo));

      DataNode<LibraryDependencyData> parentDep = stubEdgeNode("p", "parent", "1.0.0");
      DataNode<LibraryDependencyData> mergedDep = mock(DataNode.class);
      LibraryDependencyData mergedData = mock(LibraryDependencyData.class);
      LibraryData mergedTarget = mock(LibraryData.class);
      when(mergedDep.getData()).thenReturn(mergedData);
      when(mergedData.getTarget()).thenReturn(mergedTarget);
      when(mergedTarget.getGroupId()).thenReturn(null);
      when(mergedTarget.getArtifactId()).thenReturn(null);
      when(mergedTarget.getVersion()).thenReturn("1.0.0");
      when(mergedTarget.getPaths(LibraryPathType.BINARY))
          .thenReturn(
              Set.of(
                  "C:\\Users\\dev\\.gradle\\caches\\modules-2\\files-2.1\\g\\a\\1.0\\a-1.0.jar"));

      DataNode<ModuleData> moduleNode = mock(DataNode.class);
      DataNode<LibraryData> recoveredLib = libraryNode(libraryData("g", "a", "1.0.0"));
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.MODULE)))
          .thenReturn(List.of(moduleNode));
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of());
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(moduleNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of(recoveredLib));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(moduleNode), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(parentDep));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(parentDep), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(mergedDep));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(mergedDep), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of());

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: the recovered chain is the real parent path, not the synthetic single-node one.
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains()).containsExactly(List.of("p:parent", "g:a"));
    }

    @Test
    @DisplayName("should_fall_back_to_a_single_node_chain_when_no_edge_reaches_the_coordinate")
    void shouldFallBackToASingleNodeChainWhenNoEdgeReachesTheCoordinate() {
      // Given: a library the Gradle model carries with no incoming edge anywhere.
      when(mavenProjectsManager.hasProjects()).thenReturn(false);

      ExternalProjectInfo projectInfo = mock(ExternalProjectInfo.class);
      DataNode<ProjectData> projectNode = mock(DataNode.class);
      when(projectInfo.getExternalProjectStructure()).thenReturn(projectNode);
      when(projectDataManager.getExternalProjectsData(project, GradleConstants.SYSTEM_ID))
          .thenReturn(List.of(projectInfo));

      LibraryData lostData = libraryData("lost", "a", "3.0.0");
      when(lostData.getPaths(LibraryPathType.BINARY)).thenReturn(Set.of());
      DataNode<LibraryData> lostLib = libraryNode(lostData);

      DataNode<ModuleData> moduleNode = mock(DataNode.class);
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.MODULE)))
          .thenReturn(List.of(moduleNode));
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of());
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(moduleNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of(lostLib));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(moduleNode), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of());

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: the finding stays visible with the legacy single-node chain (announced by a WARN).
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains()).containsExactly(List.of("lost:a"));
    }

    @Test
    @DisplayName("should_prepend_the_platform_pseudo_root_when_the_edge_scope_is_provided")
    void shouldPrependThePlatformPseudoRootWhenTheEdgeScopeIsProvided() {
      // Given: a provided edge like the ones the intellijPlatform block adds to the classpath.
      setupGradleModuleWith(
          List.of(libraryNode(libraryData("at.yawk.lz4", "lz4-java", "1.11.3"))),
          List.of(stubEdgeNode("at.yawk.lz4", "lz4-java", "1.11.3", DependencyScope.PROVIDED)));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: the chain names the platform toolchain, not the build script.
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains())
          .containsExactly(List.of(DependencyProvenance.PLATFORM_ROOT, "at.yawk.lz4:lz4-java"));
    }

    @Test
    @DisplayName("should_prepend_the_pseudo_root_when_the_target_group_is_bundled")
    void shouldPrependThePseudoRootWhenTheTargetGroupIsBundled() {
      // Given: a library the IDE toolchain registers under the bundledModule pseudo-group.
      setupGradleModuleWith(
          List.of(
              libraryNode(libraryData("bundledModule", "intellij.java.core", "IU-263.7307.200"))),
          List.of(stubEdgeNode("bundledModule", "intellij.java.core", "IU-263.7307.200")));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains())
          .containsExactly(
              List.of(DependencyProvenance.PLATFORM_ROOT, "bundledModule:intellij.java.core"));
    }

    @Test
    @DisplayName(
        "should_prepend_the_pseudo_root_when_the_jar_lives_in_the_extracted_ide_distribution")
    void shouldPrependThePseudoRootWhenTheJarLivesInTheExtractedIdeDistribution() {
      // Given: a normal GAV whose artifact lives in the extracted IDE distribution.
      LibraryData extracted = libraryData("com.intellij.xml", "intellij.xml.core", "1.0.0");
      when(extracted.getPaths(LibraryPathType.BINARY))
          .thenReturn(
              Set.of(
                  "/home/user/.gradle/caches/9.8.2/transforms/674efdfafc2bdf533321210823"
                      + "/transformed/extracted/plugins/xml-plugin/lib/modules/"
                      + "intellij.xml.core.jar"));
      setupGradleModuleWith(List.of(libraryNode(extracted)), List.of(stubEdgeNode(extracted)));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains())
          .containsExactly(
              List.of(DependencyProvenance.PLATFORM_ROOT, "com.intellij.xml:intellij.xml.core"));
    }

    @Test
    @DisplayName("should_not_prepend_the_pseudo_root_for_plain_build_script_edges")
    void shouldNotPrependThePseudoRootForPlainBuildScriptEdges() {
      // Given: a build-script edge with a normal scope and a normal Maven cache path.
      setupGradleModuleWith(
          List.of(libraryNode(libraryData("com.example", "plain-lib", "2.0.0"))),
          List.of(stubEdgeNode("com.example", "plain-lib", "2.0.0", DependencyScope.RUNTIME)));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains())
          .containsExactly(List.of("com.example:plain-lib"));
    }

    @Test
    @DisplayName("should_not_remark_nested_platform_edges")
    void shouldNotRemarkNestedPlatformEdges() {
      // Given: user edge → platform edge → nested child; only the chain root may carry the marker.
      DataNode<LibraryDependencyData> userEdge =
          stubEdgeNode("p:root", "root", "1.0.0", DependencyScope.RUNTIME);
      DataNode<LibraryDependencyData> platformEdge =
          stubEdgeNode("bundledPlugin", "xml", "IU-263.7307.200", DependencyScope.PROVIDED);
      DataNode<LibraryDependencyData> childEdge =
          stubEdgeNode("tools.jackson.core", "jackson-core", "3.1.4");
      setupGradleModuleWith(
          List.of(
              libraryNode(libraryData("p:root", "root", "1.0.0")),
              libraryNode(libraryData("bundledPlugin", "xml", "IU-263.7307.200")),
              libraryNode(libraryData("tools.jackson.core", "jackson-core", "3.1.4"))),
          List.of(userEdge));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(userEdge), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(platformEdge));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(
                  eq(platformEdge), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(childEdge));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(childEdge), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of());

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: children inherit the path; no nested platform edge re-marks the chain.
      assertThat(results).hasSize(3);
      assertThat(chainsOf(results, "1.0.0")).containsExactly(List.of("p:root:root"));
      assertThat(chainsOf(results, "IU-263.7307.200"))
          .containsExactly(List.of("p:root:root", "bundledPlugin:xml"));
      assertThat(chainsOf(results, "3.1.4"))
          .containsExactly(
              List.of("p:root:root", "bundledPlugin:xml", "tools.jackson.core:jackson-core"));
    }

    @Test
    @DisplayName("should_prepend_the_platform_pseudo_root_for_toolchain_test_ui_modules")
    void shouldPrependThePlatformPseudoRootForToolchainTestUiModules() {
      // Given: the toolchain-injected testUi module; its edges carry a plain runtime scope, but the
      // build script never declares this source set, so their classpath is the IDE platform's.
      when(mavenProjectsManager.hasProjects()).thenReturn(false);

      ExternalProjectInfo projectInfo = mock(ExternalProjectInfo.class);
      DataNode<ProjectData> projectNode = mock(DataNode.class);
      when(projectInfo.getExternalProjectStructure()).thenReturn(projectNode);
      when(projectDataManager.getExternalProjectsData(project, GradleConstants.SYSTEM_ID))
          .thenReturn(List.of(projectInfo));

      ModuleData testUiData = mock(ModuleData.class);
      when(testUiData.getModuleName()).thenReturn("vulnspotter-plugin.testUi");
      DataNode<ModuleData> testUiModule = mock(DataNode.class);
      when(testUiModule.getData()).thenReturn(testUiData);
      DataNode<LibraryDependencyData> lz4Edge =
          stubEdgeNode("at.yawk.lz4", "lz4-java", "1.11.3", DependencyScope.RUNTIME);

      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.MODULE)))
          .thenReturn(List.of(testUiModule));
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of());
      DataNode<LibraryData> lz4Lib = libraryNode(libraryData("at.yawk.lz4", "lz4-java", "1.11.3"));
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(testUiModule), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of(lz4Lib));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(
                  eq(testUiModule), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of(lz4Edge));
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(lz4Edge), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(List.of());

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: the toolchain module marks the whole classpath as platform-provided.
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains())
          .containsExactly(List.of(DependencyProvenance.PLATFORM_ROOT, "at.yawk.lz4:lz4-java"));
    }

    @Test
    @DisplayName("should_build_chains_from_the_external_project_source_sets")
    void shouldBuildChainsFromTheExternalProjectSourceSets() {
      // Given: the resolver's ExternalProject with the resolved source-set graph (2026.3 syncs).
      setupGradleModuleWith(
          List.of(
              libraryNode(libraryData("com.example", "root", "1.0.0")),
              libraryNode(libraryData("com.example", "transitive", "2.0.0"))),
          List.of());
      stubExternalProject(
          externalProject(
              Map.of(
                  "main",
                  externalSourceSet(
                      "main",
                      externalLibraryDependency(
                          "com.example",
                          "root",
                          "1.0.0",
                          "COMPILE",
                          List.of(
                              externalLibraryDependency(
                                  "com.example", "transitive", "2.0.0", "COMPILE", List.of())))))));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: the chain states the declared dependency and its resolved transitives.
      assertThat(results).hasSize(2);
      assertThat(chainsOf(results, "1.0.0")).containsExactly(List.of("com.example:root"));
      assertThat(chainsOf(results, "2.0.0"))
          .containsExactly(List.of("com.example:root", "com.example:transitive"));
    }

    @Test
    @DisplayName("should_prepend_the_platform_pseudo_root_for_provided_source_set_dependencies")
    void shouldPrependThePlatformPseudoRootForProvidedSourceSetDependencies() {
      // Given: a source-set dependency the platform toolchain provides (PROVIDED scope).
      setupGradleModuleWith(
          List.of(libraryNode(libraryData("at.yawk.lz4", "lz4-java", "1.11.3"))), List.of());
      stubExternalProject(
          externalProject(
              Map.of(
                  "main",
                  externalSourceSet(
                      "main",
                      externalLibraryDependency(
                          "at.yawk.lz4", "lz4-java", "1.11.3", "PROVIDED", List.of())))));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains())
          .containsExactly(List.of(DependencyProvenance.PLATFORM_ROOT, "at.yawk.lz4:lz4-java"));
    }

    @Test
    @DisplayName("should_prepend_the_pseudo_root_for_dependencies_of_the_test_ui_source_set")
    void shouldPrependThePseudoRootForDependenciesOfTheTestUiSourceSet() {
      // Given: the whole testUi source set belongs to the IDE platform's classpath.
      setupGradleModuleWith(
          List.of(libraryNode(libraryData("at.yawk.lz4", "lz4-java", "1.11.3"))), List.of());
      stubExternalProject(
          externalProject(
              Map.of(
                  "testUi",
                  externalSourceSet(
                      "testUi",
                      externalLibraryDependency(
                          "at.yawk.lz4", "lz4-java", "1.11.3", "COMPILE", List.of())))));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains())
          .containsExactly(List.of(DependencyProvenance.PLATFORM_ROOT, "at.yawk.lz4:lz4-java"));
    }

    @Test
    @DisplayName("should_ignore_file_collection_and_project_dependencies_without_failing")
    void shouldIgnoreFileCollectionAndProjectDependenciesWithoutFailing() {
      // Given: a file-collection root carrying a project dependency with a nested GAV library.
      setupGradleModuleWith(
          List.of(libraryNode(libraryData("com.example", "nested", "1.0.0"))), List.of());
      stubExternalProject(
          externalProject(
              Map.of(
                  "main",
                  externalSourceSet(
                      "main",
                      fileCollectionDependency(
                          List.of(
                              projectDependency(
                                  ":another",
                                  List.of(
                                      externalLibraryDependency(
                                          "com.example",
                                          "nested",
                                          "1.0.0",
                                          "COMPILE",
                                          List.of())))))))));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: only the nested GAV coordinate enters, with its real path.
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains()).containsExactly(List.of("com.example:nested"));
    }

    @Test
    @DisplayName("should_skip_source_set_chains_when_external_project_data_is_missing")
    void shouldSkipSourceSetChainsWhenExternalProjectDataIsMissing() {
      // Given: no ExternalProject in the sync data; the v1 module walk stays the only source.
      DataNode<LibraryDependencyData> plainEdge =
          stubEdgeNode("g:a", "a", "1.0.0", DependencyScope.RUNTIME);
      setupGradleModuleWith(
          List.of(libraryNode(libraryData("g:a", "a", "1.0.0"))), List.of(plainEdge));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).dependencyChains()).containsExactly(List.of("g:a:a"));
    }

    @Test
    @DisplayName("should_prefer_source_set_chains_over_the_single_node_fallback")
    void shouldPreferSourceSetChainsOverTheSingleNodeFallback() {
      // Given: a library with no module edge but a real chain inside the ExternalProject.
      setupGradleModuleWith(List.of(libraryNode(libraryData("lost:a", "a", "3.0.0"))), List.of());
      stubExternalProject(
          externalProject(
              Map.of(
                  "main",
                  externalSourceSet(
                      "main",
                      externalLibraryDependency(
                          "root:a",
                          "a",
                          "1.0.0",
                          "COMPILE",
                          List.of(
                              externalLibraryDependency(
                                  "lost:a", "a", "3.0.0", "COMPILE", List.of())))))));

      // When
      List<OsvPackage> results = DependencyParser.parseDependencies(project).packages();

      // Then: the chain states the parent; no single-node fallback, no fallback warning.
      assertThat(results).hasSize(1);
      assertThat(chainsOf(results, "3.0.0")).containsExactly(List.of("root:a:a", "lost:a:a"));
    }

    /** Standard Gradle sync fixtures: one module holding the given libraries and root edges. */
    private DataNode<ProjectData> setupGradleModuleWith(
        List<DataNode<LibraryData>> libraries, List<DataNode<LibraryDependencyData>> edges) {
      when(mavenProjectsManager.hasProjects()).thenReturn(false);

      ExternalProjectInfo projectInfo = mock(ExternalProjectInfo.class);
      DataNode<ProjectData> projectNode = mock(DataNode.class);
      when(projectInfo.getExternalProjectStructure()).thenReturn(projectNode);
      when(projectInfo.getExternalProjectPath()).thenReturn("root");
      when(projectDataManager.getExternalProjectsData(project, GradleConstants.SYSTEM_ID))
          .thenReturn(List.of(projectInfo));

      DataNode<ModuleData> moduleNode = mock(DataNode.class);
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.MODULE)))
          .thenReturn(List.of(moduleNode));
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(projectNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(List.of());
      externalSystemStatic
          .when(() -> ExternalSystemApiUtil.findAll(eq(moduleNode), eq(ProjectKeys.LIBRARY)))
          .thenReturn(libraries);
      externalSystemStatic
          .when(() ->
              ExternalSystemApiUtil.getChildren(eq(moduleNode), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
          .thenReturn(edges);
      for (DataNode<LibraryDependencyData> edge : edges) {
        externalSystemStatic
            .when(() ->
                ExternalSystemApiUtil.getChildren(eq(edge), eq(ProjectKeys.LIBRARY_DEPENDENCY)))
            .thenReturn(List.of());
      }
      return projectNode;
    }

    /** Stubs the ExternalProject cache the parser goes through for the source-set chains. */
    private void stubExternalProject(ExternalProject rootProject) {
      when(externalProjectDataCache.getRootExternalProject(anyString())).thenReturn(rootProject);
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
