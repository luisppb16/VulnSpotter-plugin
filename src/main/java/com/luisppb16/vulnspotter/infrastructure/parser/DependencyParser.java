/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.parser;

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
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
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
  // Exact npm version: "1.2.3", "1.2.3-beta.2" or "1.2.3+build.1" (after stripping a leading ^/~/v)
  private static final Pattern NPM_EXACT_VERSION_PATTERN =
      Pattern.compile("^\\d+\\.\\d+\\.\\d+(?:-[\\w.+-]+)?(?:\\+[\\w.+-]+)?$");
  // requirements.txt exact pin: "name[extras] == version" (extras dropped from the name)
  private static final Pattern REQUIREMENT_PATTERN =
      Pattern.compile("^([A-Za-z0-9_.-]+)(?:\\[[^]]*])?\\s*===?\\s*([\\w.!+-]+)$");
  // Matches Gradle cache path: .../modules-2/files-2.1/group/artifact/version/...
  private static final Pattern GRADLE_CACHE_PATTERN =
      Pattern.compile(".*/modules-2/files-2\\.1/([^/]+)/([^/]+)/([^/]+)/.*");
  // Matches a Maven local-repository path: .../repository/<group path>/<artifact>/<version>/<jar>
  private static final Pattern MAVEN_REPO_PATTERN =
      Pattern.compile(".*/repository/(.+)/([^/]+)/([^/]+)/[^/]+-[^/]+\\.jar$");
  // Matches a package-lock v2/v3 key like "node_modules/foo" or
  // "node_modules/foo/node_modules/bar".
  private static final Pattern NPM_LOCK_KEY_PATTERN = Pattern.compile("^node_modules/(.+)$");
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

    // Library-table fallbacks (3-4) are redundant when a managed build system already provided
    // the dependency graph, but manifest parsers (5-7) always run so polyglot projects
    // (e.g. Gradle backend + npm frontend) still get their other ecosystems scanned.
    if (!isManagedProject) {
      // 3. Fallback: OrderEnumerator (Module Libraries)
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

      // 4. Fallback: Project Libraries
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
    }

    // 5. Node.js (package-lock.json preferred, else package.json exact pins)
    try {
      parseNpm(project, allPackages);
    } catch (Exception e) {
      LOG.warn("Failed to parse npm dependencies", e);
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

  /**
   * Parses npm dependencies. A lockfile (package-lock.json / npm-shrinkwrap.json) is preferred
   * because it carries the exact installed version of every package, including transitive ones and
   * ranges resolved from package.json. When no lockfile exists, every package.json under the
   * project (skipping node_modules) is scanned for exact version pins only — ranges are dropped
   * because they do not identify an installed version.
   */
  private static void parseNpm(Project project, List<OsvPackage> allPackages) throws IOException {
    String basePath = project.getBasePath();
    if (basePath == null) return;
    Path root = Paths.get(basePath);

    Path lockPath = root.resolve("package-lock.json");
    Path shrinkPath = root.resolve("npm-shrinkwrap.json");
    if (Files.exists(lockPath)) {
      parsePackageLock(lockPath, allPackages);
      return;
    }
    if (Files.exists(shrinkPath)) {
      parsePackageLock(shrinkPath, allPackages);
      return;
    }

    List<Path> packageJsonFiles = new ArrayList<>();
    collectPackageJsonFiles(root, packageJsonFiles, 0);
    for (Path pkgJsonPath : packageJsonFiles) {
      parsePackageJsonDeps(pkgJsonPath, allPackages);
    }
  }

  /** Reads a package-lock v2/v3 {@code packages} map (or v1 {@code dependencies}) into packages. */
  private static void parsePackageLock(Path lockPath, List<OsvPackage> allPackages)
      throws IOException {
    JsonNode root = MAPPER.readTree(lockPath.toFile());
    JsonNode packages = root.get("packages");
    if (packages != null && packages.isObject()) {
      packages
          .fieldNames()
          .forEachRemaining(
              key -> {
                // The root project itself is keyed as "" ; nested node_modules entries carry the
                // resolved version. Take the package name after the last "node_modules/" segment.
                if (key.isEmpty() || !key.startsWith("node_modules/")) return;
                Matcher m = NPM_LOCK_KEY_PATTERN.matcher(key);
                if (!m.matches()) return;
                String name = m.group(1);
                int nested = name.lastIndexOf("/node_modules/");
                if (nested >= 0) {
                  name = name.substring(nested + "/node_modules/".length());
                }
                JsonNode versionNode = packages.get(key).get("version");
                if (versionNode != null && !versionNode.isNull()) {
                  String version = versionNode.asText().trim();
                  if (!version.isEmpty() && !"undefined".equals(version)) {
                    allPackages.add(new OsvPackage(name, "npm", version));
                  }
                }
              });
      return;
    }
    // Lockfile v1: "dependencies" is a nested tree; each node has a "version" and optional "deps".
    JsonNode dependencies = root.get("dependencies");
    if (dependencies != null && dependencies.isObject()) {
      collectNpmLockV1Dependencies(dependencies, allPackages);
    }
  }

  private static void collectNpmLockV1Dependencies(JsonNode deps, List<OsvPackage> allPackages) {
    deps.fieldNames()
        .forEachRemaining(
            name -> {
              JsonNode node = deps.get(name);
              JsonNode versionNode = node.get("version");
              if (versionNode != null && !versionNode.isNull()) {
                String version = versionNode.asText().trim();
                if (!version.isEmpty()) {
                  allPackages.add(new OsvPackage(name, "npm", version));
                }
              }
              JsonNode nested = node.get("dependencies");
              if (nested != null && nested.isObject()) {
                collectNpmLockV1Dependencies(nested, allPackages);
              }
            });
  }

  /** Bounded recursive discovery of package.json files, skipping node_modules and .git. */
  private static void collectPackageJsonFiles(Path dir, List<Path> results, int depth) {
    if (depth > 6) return;
    String name = dir.getFileName() != null ? dir.getFileName().toString() : "";
    if (depth > 0 && ("node_modules".equals(name) || ".git".equals(name))) return;
    try (var stream = Files.list(dir)) {
      List<Path> entries = stream.toList();
      for (Path entry : entries) {
        if (Files.isDirectory(entry)) {
          collectPackageJsonFiles(entry, results, depth + 1);
        } else if ("package.json".equals(entry.getFileName().toString())) {
          results.add(entry);
        }
      }
    } catch (IOException e) {
      LOG.debug("Skipping directory during package.json discovery: " + dir, e);
    }
  }

  private static void parsePackageJsonDeps(Path pkgJsonPath, List<OsvPackage> allPackages)
      throws IOException {
    JsonNode node = MAPPER.readTree(pkgJsonPath.toFile());
    processJsonDependencies(node, "dependencies", allPackages);
    processJsonDependencies(node, "devDependencies", allPackages);
    processJsonDependencies(node, "peerDependencies", allPackages);
    processJsonDependencies(node, "optionalDependencies", allPackages);
  }

  private static void processJsonDependencies(
      JsonNode root, String fieldName, List<OsvPackage> allPackages) {
    if (root.has(fieldName)) {
      JsonNode deps = root.get(fieldName);
      deps.fieldNames()
          .forEachRemaining(
              name -> {
                // Only exact versions can be checked against OSV. Ranges (">=1.2 <2", "1.x",
                // "~1.2") don't identify the installed version, and mangling them produces
                // non-existent versions that OSV silently reports as safe.
                String raw = deps.get(name).asText().trim();
                String candidate =
                    (raw.startsWith("^") || raw.startsWith("~")) ? raw.substring(1) : raw;
                if (candidate.startsWith("v")) {
                  candidate = candidate.substring(1);
                }
                if (NPM_EXACT_VERSION_PATTERN.matcher(candidate).matches()) {
                  allPackages.add(new OsvPackage(name, "npm", candidate));
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
    parseRequirementsFile(reqTxtPath, allPackages, new HashSet<>());
  }

  private static void parseRequirementsFile(
      Path reqTxtPath, List<OsvPackage> allPackages, Set<Path> visited) throws IOException {
    if (!visited.add(reqTxtPath.toAbsolutePath().normalize())) return;
    List<String> lines = Files.readAllLines(reqTxtPath);
    for (String rawLine : lines) {
      String line = rawLine.trim();
      if (line.isEmpty() || line.startsWith("#")) continue;

      // Follow "-r other.txt" / "--requirements other.txt" includes (relative to this file).
      if (line.startsWith("-r ") || line.startsWith("--requirements ")) {
        String include = line.replaceFirst("-r |--requirements ", "").trim();
        Path included = reqTxtPath.resolveSibling(include).normalize();
        if (Files.exists(included)) {
          parseRequirementsFile(included, allPackages, visited);
        }
        continue;
      }
      if (line.startsWith("-")) continue; // other pip options (-e, -c, --hash, …)

      // Strip inline comments and environment markers before matching.
      int hashIdx = line.indexOf('#');
      if (hashIdx >= 0) line = line.substring(0, hashIdx).trim();
      int markerIdx = line.indexOf(';');
      if (markerIdx >= 0) line = line.substring(0, markerIdx).trim();

      // Drop trailing pip options such as " --hash=sha256:…" / " --hash abc".
      line = stripPipOptions(line).trim();
      if (line.isEmpty()) continue;

      Matcher reqMatcher = REQUIREMENT_PATTERN.matcher(line);
      if (reqMatcher.matches()) {
        allPackages.add(new OsvPackage(reqMatcher.group(1), "PyPI", reqMatcher.group(2)));
      }
    }
  }

  /** Removes trailing {@code --option[=value]} tokens from a requirement line. */
  private static String stripPipOptions(String line) {
    String result = line;
    int idx;
    while ((idx = result.indexOf(" --")) >= 0) {
      result = result.substring(0, idx);
    }
    return result;
  }

  private static void parseGoMod(Project project, List<OsvPackage> allPackages) throws IOException {
    String basePath = project.getBasePath();
    if (basePath == null) return;
    Path goModPath = Paths.get(basePath, "go.mod");
    if (!Files.exists(goModPath)) return;

    List<String> lines = Files.readAllLines(goModPath);
    // First pass: collect replace directives so the effective module path/version is queried.
    Map<String, String[]> replaces = new HashMap<>();
    boolean inReplaceBlock = false;
    for (String rawLine : lines) {
      String line = rawLine.trim();
      if (line.startsWith("replace (")) {
        inReplaceBlock = true;
        continue;
      }
      if (inReplaceBlock && line.equals(")")) {
        inReplaceBlock = false;
        continue;
      }
      String replaceBody = null;
      if (inReplaceBlock) {
        replaceBody = line;
      } else if (line.startsWith("replace ")) {
        replaceBody = line.substring("replace ".length()).trim();
      }
      if (replaceBody == null || replaceBody.isEmpty() || replaceBody.startsWith("//")) continue;
      parseReplaceDirective(replaceBody, replaces);
    }

    // Second pass: collect require directives, applying replaces.
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
          || line.startsWith("//")
          || line.startsWith("replace ")
          || line.startsWith("replace(")) {
        continue;
      }
      if (!inRequireBlock && !line.startsWith("require ")) {
        continue;
      }
      String depLine = inRequireBlock ? line : line.substring("require ".length()).trim();
      // Drop trailing comments.
      int c = depLine.indexOf("//");
      if (c >= 0) depLine = depLine.substring(0, c).trim();
      String[] parts = depLine.split("\\s+");
      if (parts.length >= 2) {
        String modulePath = parts[0];
        String version = parts[1].replaceFirst("^v", "");
        String[] replacement = replaces.get(modulePath);
        if (replacement != null) {
          modulePath = replacement[0];
          version = replacement[1];
        }
        allPackages.add(new OsvPackage(modulePath, "Go", version));
      }
    }
  }

  /**
   * Parses a single {@code replace} body into {@code replaces} as {@code oldPath -> [newPath,
   * newVersion]}. Local-path replacements and bare {@code replace old => new} (no version) are
   * skipped because they cannot be queried against OSV.
   */
  private static void parseReplaceDirective(String body, Map<String, String[]> replaces) {
    int arrow = body.indexOf("=>");
    if (arrow < 0) return;
    String left = body.substring(0, arrow).trim();
    String right = body.substring(arrow + 2).trim();
    String[] leftParts = left.split("\\s+");
    if (leftParts.length < 1) return;
    String oldPath = leftParts[0];
    String[] rightParts = right.split("\\s+");
    if (rightParts.length < 1) return;
    String newPath = rightParts[0];
    // Local path replacements (./... or /...) cannot be queried.
    if (newPath.startsWith("./") || newPath.startsWith("../") || newPath.startsWith("/")) return;
    String newVersion = rightParts.length >= 2 ? rightParts[1].replaceFirst("^v", "") : null;
    if (newVersion == null) return;
    replaces.put(oldPath, new String[] {newPath, newVersion});
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
      // Canonical ordering is g:a:v[:classifier][:type]; the version is parts[2] when it looks like
      // a version, otherwise (e.g. "g:a:test-jar:tests:1.0") fall back to the last segment so the
      // classifier is not mistaken for the version.
      String version = parts[2];
      if (!startsWithDigit(version) && parts.length >= 4) {
        version = parts[parts.length - 1];
      }

      // Handle artifacts with packaging suffix (e.g., 1.0@aar)
      int atIndex = version.indexOf('@');
      if (atIndex > 0) {
        version = version.substring(0, atIndex);
      }

      if (!parts[0].isBlank() && !parts[1].isBlank() && startsWithDigit(version)) {
        return new OsvPackage(fullName, MAVEN_ECOSYSTEM, version, Set.of(List.of(fullName)));
      }
    }
    return null;
  }

  private static boolean startsWithDigit(String value) {
    return !value.isEmpty() && Character.isDigit(value.charAt(0));
  }

  private static OsvPackage parseFromLibraryFiles(Library library) {
    VirtualFile[] files = library.getFiles(OrderRootType.CLASSES);
    for (VirtualFile file : files) {
      String path = file.getPath();
      OsvPackage pkg = parseFromFilePath(path);
      if (pkg != null) {
        return pkg;
      }
      // A bare jar filename only yields the artifactId; OSV's Maven ecosystem requires
      // "group:artifact", so querying with just the artifact name always returns "no
      // vulnerabilities" — a silent false negative. Skip these libraries instead.
      LOG.debug("Skipping library without resolvable Maven coordinates: " + file.getName());
    }
    return null;
  }

  private static OsvPackage parseFromFilePath(String path) {
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
    Matcher mavenMatcher = MAVEN_REPO_PATTERN.matcher(path);
    if (mavenMatcher.matches()) {
      String group = mavenMatcher.group(1).replace('/', ':');
      String artifact = mavenMatcher.group(2);
      String version = mavenMatcher.group(3);
      String fullName = group + ":" + artifact;
      return new OsvPackage(fullName, MAVEN_ECOSYSTEM, version, Set.of(List.of(fullName)));
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
