/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.projectsapo.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.externalSystem.model.DataNode;
import com.intellij.openapi.externalSystem.model.ExternalProjectInfo;
import com.intellij.openapi.externalSystem.model.ProjectKeys;
import com.intellij.openapi.externalSystem.model.project.LibraryData;
import com.intellij.openapi.externalSystem.model.project.ModuleData;
import com.intellij.openapi.externalSystem.model.project.ProjectData;
import com.intellij.openapi.externalSystem.service.project.ProjectDataManager;
import com.intellij.openapi.externalSystem.util.ExternalSystemApiUtil;
import com.intellij.openapi.module.Module;
import com.intellij.openapi.module.ModuleManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.roots.OrderEnumerator;
import com.intellij.openapi.roots.OrderRootType;
import com.intellij.openapi.roots.libraries.Library;
import com.intellij.openapi.roots.libraries.LibraryTable;
import com.intellij.openapi.roots.libraries.LibraryTablesRegistrar;
import com.intellij.openapi.vfs.VirtualFile;
import com.projectsapo.model.OsvPackage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.idea.maven.model.MavenArtifact;
import org.jetbrains.idea.maven.model.MavenArtifactNode;
import org.jetbrains.idea.maven.project.MavenProject;
import org.jetbrains.idea.maven.project.MavenProjectsManager;
import org.jetbrains.plugins.gradle.util.GradleConstants;

/**
 * Utility class to parse dependencies and their transitive chains. Fixed to avoid including the
 * project name as a parent dependency.
 */
public final class DependencyParser {

  private static final Logger LOG = Logger.getInstance(DependencyParser.class);
  private static final Pattern JAR_VERSION_PATTERN = Pattern.compile("^(.+?)-(\\d[\\w.-]*)$");
  // Matches Gradle cache path: .../modules-2/files-2.1/group/artifact/version/...
  private static final Pattern GRADLE_CACHE_PATTERN =
      Pattern.compile(".*/modules-2/files-2\\.1/([^/]+)/([^/]+)/([^/]+)/.*");
  private static final String MAVEN_ECOSYSTEM = "Maven";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private DependencyParser() {
    throw new UnsupportedOperationException("Utility class");
  }

  public static List<OsvPackage> parseDependencies(@NotNull Project project) {
    List<OsvPackage> allPackages = new ArrayList<>();
    boolean isManagedProject = false;

    // 1. Maven: Real tree support
    try {
      MavenProjectsManager mavenManager = MavenProjectsManager.getInstance(project);
      if (mavenManager != null && mavenManager.hasProjects()) {
        allPackages.addAll(parseMavenDependencies(mavenManager));
        isManagedProject = true;
      }
    } catch (Exception e) {
      LOG.warn("Failed to parse Maven dependencies", e);
    }

    // 2. Gradle: External System support
    try {
      Collection<ExternalProjectInfo> gradleProjects =
          ProjectDataManager.getInstance()
              .getExternalProjectsData(project, GradleConstants.SYSTEM_ID);
      if (!gradleProjects.isEmpty()) {
        allPackages.addAll(parseGradleDependencies(gradleProjects));
        isManagedProject = true;
      }
    } catch (Exception e) {
      LOG.warn("Failed to parse Gradle dependencies", e);
    }

    // If managed build systems are detected, we skip manual fallbacks to avoid redundant scanning
    // and potential performance issues with large projects.
    if (isManagedProject) {
      return deduplicateAndSort(allPackages);
    }

    // 3. Fallback: OrderEnumerator (Module Libraries) - Always run to catch manual libs
    try {
      Module[] modules = ModuleManager.getInstance(project).getModules();
      for (Module module : modules) {
        OrderEnumerator.orderEntries(module)
            .recursively()
            .librariesOnly()
            .forEachLibrary(
                library -> {
                  OsvPackage pkg = parseLibrary(library);
                  if (pkg != null) {
                    allPackages.add(pkg);
                  }
                  return true;
                });
      }
    } catch (Exception e) {
      LOG.warn("Failed to parse module dependencies via OrderEnumerator", e);
    }

    // 4. Fallback: Project Libraries - Always run
    try {
      LibraryTable projectLibraryTable =
          LibraryTablesRegistrar.getInstance().getLibraryTable(project);
      for (Library library : projectLibraryTable.getLibraries()) {
        OsvPackage pkg = parseLibrary(library);
        if (pkg != null) {
          allPackages.add(pkg);
        }
      }
    } catch (Exception e) {
      LOG.warn("Failed to parse project libraries", e);
    }

    // 5. Node.js (package.json)
    try {
      parsePackageJson(project, allPackages);
    } catch (Exception e) {
      LOG.warn("Failed to parse package.json", e);
    }

    // 6. Python (requirements.txt)
    try {
      parseRequirementsTxt(project, allPackages);
    } catch (Exception e) {
      LOG.warn("Failed to parse requirements.txt", e);
    }

    // 7. Go (go.mod)
    try {
      parseGoMod(project, allPackages);
    } catch (Exception e) {
      LOG.warn("Failed to parse go.mod", e);
    }

    return deduplicateAndSort(allPackages);
  }

  private static void parsePackageJson(Project project, List<OsvPackage> allPackages)
      throws IOException {
    String basePath = project.getBasePath();
    if (basePath == null) return;
    Path pkgJsonPath = Paths.get(basePath, "package.json");
    if (!Files.exists(pkgJsonPath)) return;

    JsonNode node = MAPPER.readTree(pkgJsonPath.toFile());
    processJsonDependencies(node, "dependencies", allPackages);
    processJsonDependencies(node, "devDependencies", allPackages);
  }

  private static void processJsonDependencies(
      JsonNode root, String fieldName, List<OsvPackage> allPackages) {
    if (root.has(fieldName)) {
      JsonNode deps = root.get(fieldName);
      deps.fieldNames()
          .forEachRemaining(
              name -> {
                String version = deps.get(name).asText().replaceAll("[^0-9.]", "");
                if (!version.isEmpty()) {
                  allPackages.add(new OsvPackage(name, "npm", version));
                }
              });
    }
  }

  private static void parseRequirementsTxt(Project project, List<OsvPackage> allPackages)
      throws IOException {
    String basePath = project.getBasePath();
    if (basePath == null) return;
    Path reqTxtPath = Paths.get(basePath, "requirements.txt");
    if (!Files.exists(reqTxtPath)) return;

    List<String> lines = Files.readAllLines(reqTxtPath);
    for (String rawLine : lines) {
      String line = rawLine.trim();
      if (line.isEmpty() || line.startsWith("#") || line.startsWith("-")) continue;
      int hashIdx = line.indexOf('#');
      if (hashIdx >= 0) {
        line = line.substring(0, hashIdx).trim();
      }
      if (line.contains("==")) {
        String[] parts = line.split("==");
        if (parts.length == 2) {
          allPackages.add(new OsvPackage(parts[0].trim(), "PyPI", parts[1].trim()));
        }
      }
    }
  }

  private static void parseGoMod(Project project, List<OsvPackage> allPackages) throws IOException {
    String basePath = project.getBasePath();
    if (basePath == null) return;
    Path goModPath = Paths.get(basePath, "go.mod");
    if (!Files.exists(goModPath)) return;

    List<String> lines = Files.readAllLines(goModPath);
    boolean inRequireBlock = false;
    for (String rawLine : lines) {
      String line = rawLine.trim();
      if (line.startsWith("require (")) {
        inRequireBlock = true;
        continue;
      }
      if (inRequireBlock && line.equals(")")) {
        inRequireBlock = false;
        continue;
      }
      if (line.startsWith("module ")
          || line.startsWith("go ")
          || line.isEmpty()
          || line.startsWith("//")) {
        continue;
      }
      if (!inRequireBlock && !line.startsWith("require ")) {
        continue;
      }
      String depLine = inRequireBlock ? line : line.substring("require ".length()).trim();
      String[] parts = depLine.split("\\s+");
      if (parts.length >= 2) {
        String version = parts[1].replaceFirst("^v", "");
        allPackages.add(new OsvPackage(parts[0], "Go", version));
      }
    }
  }

  private static List<OsvPackage> deduplicateAndSort(List<OsvPackage> allPackages) {
    // Aggregation: Deduplicate based on name, version, ecosystem
    Map<DependencyGroupingKey, List<OsvPackage>> grouped =
        allPackages.stream()
            .collect(
                Collectors.groupingBy(
                    pkg -> new DependencyGroupingKey(pkg.name(), pkg.version(), pkg.ecosystem())));

    return grouped.values().stream()
        .map(
            group -> {
              OsvPackage representative = group.getFirst();
              Set<List<String>> allChains =
                  group.stream()
                      .map(OsvPackage::dependencyChains)
                      .flatMap(Collection::stream)
                      .collect(Collectors.toSet());
              return new OsvPackage(
                  representative.name(),
                  representative.ecosystem(),
                  representative.version(),
                  allChains);
            })
        .sorted(Comparator.comparing(OsvPackage::name))
        .toList();
  }

  private static List<OsvPackage> parseMavenDependencies(MavenProjectsManager projectsManager) {
    List<OsvPackage> dependencies = new ArrayList<>();
    for (MavenProject mavenProject : projectsManager.getProjects()) {
      for (MavenArtifactNode node : mavenProject.getDependencyTree()) {
        // Start chain with the direct dependency itself
        collectMavenDependencies(node, new ArrayList<>(), dependencies);
      }
    }
    return dependencies;
  }

  private static void collectMavenDependencies(
      MavenArtifactNode node, List<String> parentChain, List<OsvPackage> result) {
    MavenArtifact artifact = node.getArtifact();
    String fullName = artifact.getGroupId() + ":" + artifact.getArtifactId();

    List<String> currentChain = new ArrayList<>(parentChain);
    currentChain.add(fullName);

    result.add(
        new OsvPackage(fullName, MAVEN_ECOSYSTEM, artifact.getVersion(), Set.of(currentChain)));

    for (MavenArtifactNode child : node.getDependencies()) {
      collectMavenDependencies(child, currentChain, result);
    }
  }

  private static List<OsvPackage> parseGradleDependencies(
      Collection<ExternalProjectInfo> projectInfos) {
    List<OsvPackage> dependencies = new ArrayList<>();

    for (ExternalProjectInfo info : projectInfos) {
      DataNode<ProjectData> projectNode = info.getExternalProjectStructure();
      if (projectNode == null) continue;

      // Check for libraries at project level
      processLibraryNodes(
          ExternalSystemApiUtil.findAll(projectNode, ProjectKeys.LIBRARY), dependencies);

      // Check for libraries at module level
      Collection<DataNode<ModuleData>> moduleNodes =
          ExternalSystemApiUtil.findAll(projectNode, ProjectKeys.MODULE);
      for (DataNode<ModuleData> moduleNode : moduleNodes) {
        processLibraryNodes(
            ExternalSystemApiUtil.findAll(moduleNode, ProjectKeys.LIBRARY), dependencies);
      }
    }
    return dependencies;
  }

  private static void processLibraryNodes(
      Collection<DataNode<LibraryData>> libraryNodes, List<OsvPackage> dependencies) {
    for (DataNode<LibraryData> libNode : libraryNodes) {
      LibraryData data = libNode.getData();
      String group = data.getGroupId();
      String artifact = data.getArtifactId();
      String version = data.getVersion();

      if (group != null && artifact != null && version != null) {
        String fullName = group + ":" + artifact;
        dependencies.add(
            new OsvPackage(fullName, MAVEN_ECOSYSTEM, version, Set.of(List.of(fullName))));
      }
    }
  }

  private static OsvPackage parseLibrary(Library library) {
    String name = library.getName();
    if (name == null) return null;

    OsvPackage pkg = parseFromLibraryName(name);
    if (pkg != null) {
      return pkg;
    }

    return parseFromLibraryFiles(library);
  }

  private static OsvPackage parseFromLibraryName(String name) {
    String cleanName = name;
    if (cleanName.startsWith("Gradle: ")) {
      cleanName = cleanName.substring(8);
    } else if (cleanName.startsWith("Maven: ")) {
      cleanName = cleanName.substring(7);
    }

    String[] parts = cleanName.split(":");
    if (parts.length >= 3) {
      String fullName = parts[0] + ":" + parts[1];
      String version = parts[2];

      // Handle artifacts with classifiers or packaging (e.g., @aar)
      int atIndex = version.indexOf('@');
      if (atIndex > 0) {
        version = version.substring(0, atIndex);
      }

      if (!parts[0].isBlank() && !parts[1].isBlank()) {
        return new OsvPackage(fullName, MAVEN_ECOSYSTEM, version, Set.of(List.of(fullName)));
      }
    }
    return null;
  }

  private static OsvPackage parseFromLibraryFiles(Library library) {
    VirtualFile[] files = library.getFiles(OrderRootType.CLASSES);
    for (VirtualFile file : files) {
      String path = file.getPath();

      // Try Gradle Cache Pattern
      Matcher cacheMatcher = GRADLE_CACHE_PATTERN.matcher(path);
      if (cacheMatcher.matches()) {
        String group = cacheMatcher.group(1);
        String artifact = cacheMatcher.group(2);
        String version = cacheMatcher.group(3);
        return new OsvPackage(
            group + ":" + artifact,
            MAVEN_ECOSYSTEM,
            version,
            Set.of(List.of(group + ":" + artifact)));
      }

      String filename = file.getName();
      // Remove extension
      int dotIndex = filename.lastIndexOf('.');
      if (dotIndex > 0) {
        filename = filename.substring(0, dotIndex);
      }

      Matcher matcher = JAR_VERSION_PATTERN.matcher(filename);
      if (matcher.matches()) {
        String artifact = matcher.group(1);
        String version = matcher.group(2);
        return new OsvPackage(artifact, MAVEN_ECOSYSTEM, version, Set.of(List.of(artifact)));
      }
    }
    return null;
  }

  /**
   * Dedicated record for grouping to avoid string concatenation overhead.
   *
   * @param name Name of the package
   * @param version Version of the package
   * @param ecosystem Ecosystem of the package
   */
  private record DependencyGroupingKey(String name, String version, String ecosystem) {}
}
