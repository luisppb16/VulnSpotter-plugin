/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.projectsapo.util;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.intellij.openapi.application.Application;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.externalSystem.service.project.ProjectDataManager;
import com.intellij.openapi.module.Module;
import com.intellij.openapi.module.ModuleManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.roots.OrderEnumerator;
import com.intellij.openapi.roots.libraries.Library;
import com.intellij.openapi.roots.libraries.LibraryTable;
import com.intellij.openapi.roots.libraries.LibraryTablesRegistrar;
import com.intellij.util.Processor;
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
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

class DependencyParserBenchmarkTest {

  @Mock private Project project;
  @Mock private MavenProjectsManager mavenProjectsManager;
  @Mock private ProjectDataManager projectDataManager;
  @Mock private MavenProject mavenProject;
  @Mock private OrderEnumerator orderEnumerator;
  @Mock private Application application;
  @Mock private ModuleManager moduleManager;
  @Mock private Module module;
  @Mock private LibraryTablesRegistrar libraryTablesRegistrar;
  @Mock private LibraryTable libraryTable;

  private MockedStatic<MavenProjectsManager> mavenProjectsManagerMock;
  private MockedStatic<ProjectDataManager> projectDataManagerMock;
  private MockedStatic<OrderEnumerator> orderEnumeratorMock;
  private MockedStatic<ApplicationManager> applicationManagerMock;
  private MockedStatic<ModuleManager> moduleManagerMock;
  private MockedStatic<LibraryTablesRegistrar> libraryTablesRegistrarMock;
  private AutoCloseable mocks;

  @BeforeEach
  void setUp() {
    mocks = MockitoAnnotations.openMocks(this);
    mavenProjectsManagerMock = mockStatic(MavenProjectsManager.class);
    projectDataManagerMock = mockStatic(ProjectDataManager.class);
    orderEnumeratorMock = mockStatic(OrderEnumerator.class);
    applicationManagerMock = mockStatic(ApplicationManager.class);
    moduleManagerMock = mockStatic(ModuleManager.class);
    libraryTablesRegistrarMock = mockStatic(LibraryTablesRegistrar.class);

    mavenProjectsManagerMock
        .when(() -> MavenProjectsManager.getInstance(project))
        .thenReturn(mavenProjectsManager);
    projectDataManagerMock.when(ProjectDataManager::getInstance).thenReturn(projectDataManager);
    orderEnumeratorMock
        .when(() -> OrderEnumerator.orderEntries(any(Module.class)))
        .thenReturn(orderEnumerator);
    orderEnumeratorMock
        .when(() -> OrderEnumerator.orderEntries(project))
        .thenReturn(orderEnumerator);
    applicationManagerMock.when(ApplicationManager::getApplication).thenReturn(application);
    moduleManagerMock.when(() -> ModuleManager.getInstance(project)).thenReturn(moduleManager);
    libraryTablesRegistrarMock
        .when(LibraryTablesRegistrar::getInstance)
        .thenReturn(libraryTablesRegistrar);

    when(moduleManager.getModules()).thenReturn(new Module[] {module});
    when(libraryTablesRegistrar.getLibraryTable(project)).thenReturn(libraryTable);
    when(libraryTable.getLibraries()).thenReturn(new Library[0]);

    when(orderEnumerator.librariesOnly()).thenReturn(orderEnumerator);
    when(orderEnumerator.recursively()).thenReturn(orderEnumerator);
  }

  @AfterEach
  void tearDown() throws Exception {
    mavenProjectsManagerMock.close();
    projectDataManagerMock.close();
    orderEnumeratorMock.close();
    applicationManagerMock.close();
    moduleManagerMock.close();
    libraryTablesRegistrarMock.close();
    mocks.close();
  }

  @Test
  void benchmarkRedundantParsing() {
    // Setup a scenario where Maven has projects AND OrderEnumerator has the same libraries.
    int depCount = 5000;

    // 1. Setup Maven Dependencies
    when(mavenProjectsManager.hasProjects()).thenReturn(true);
    when(mavenProjectsManager.getProjects()).thenReturn(List.of(mavenProject));

    List<MavenArtifactNode> mavenNodes = new ArrayList<>(depCount);
    for (int i = 0; i < depCount; i++) {
      MavenArtifactNode node = mock(MavenArtifactNode.class);
      MavenArtifact artifact = mock(MavenArtifact.class);
      when(node.getArtifact()).thenReturn(artifact);
      when(artifact.getGroupId()).thenReturn("com.example");
      when(artifact.getArtifactId()).thenReturn("lib-" + i);
      when(artifact.getVersion()).thenReturn("1.0.0");
      when(node.getDependencies()).thenReturn(new ArrayList<>());
      mavenNodes.add(node);
    }
    when(mavenProject.getDependencyTree()).thenReturn(mavenNodes);

    // 2. Setup Gradle (empty)
    when(projectDataManager.getExternalProjectsData(project, GradleConstants.SYSTEM_ID))
        .thenReturn(Collections.emptyList());

    // 3. Setup OrderEnumerator (Same 5000 libraries)
    // We mock forEachLibrary to simulate iteration over libraries
    doAnswer(
            invocation -> {
              Processor<Library> processor = invocation.getArgument(0);
              for (int i = 0; i < depCount; i++) {
                Library library = mock(Library.class);
                when(library.getName()).thenReturn("Maven: com.example:lib-" + i + ":1.0.0");
                processor.process(library);
              }
              return null;
            })
        .when(orderEnumerator)
        .forEachLibrary(any());

    // Warmup
    for (int i = 0; i < 5; i++) {
      DependencyParser.parseDependencies(project);
    }

    // Measure
    long startTime = System.nanoTime();
    int iterations = 10;
    for (int i = 0; i < iterations; i++) {
      List<OsvPackage> result = DependencyParser.parseDependencies(project);
      if (result.size() != depCount) {
        throw new RuntimeException("Unexpected result size: " + result.size());
      }
    }
    long endTime = System.nanoTime();

    double avgTimeMs = (endTime - startTime) / (iterations * 1_000_000.0);
    System.out.println("Average execution time (Maven + Fallback): " + avgTimeMs + " ms");
  }
}
