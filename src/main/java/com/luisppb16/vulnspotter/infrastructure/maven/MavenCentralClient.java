/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.maven;

import com.intellij.openapi.application.PathManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.util.io.HttpRequests;
import com.luisppb16.vulnspotter.domain.service.VersionUtil;
import com.luisppb16.vulnspotter.settings.VulnSpotterSettings;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jetbrains.annotations.Nullable;

/**
 * Best-effort reader of Maven Central metadata for the transitive remediation: published versions
 * of a coordinate and the version a candidate parent POM (including its parent chain and imported
 * BOMs) assigns to a vulnerable child package. Every lookup degrades to an empty answer on failure
 * — network problems, unresolvable {@code ${property}} versions or exotic POMs simply yield no
 * suggestion, never an exception. POM documents are immutable per coordinate once published, so
 * they are cached in memory and on disk; version lists are session-cached only because the metadata
 * document keeps growing.
 */
public class MavenCentralClient {

  private static final Logger LOG = Logger.getInstance(MavenCentralClient.class);

  private static final String REPOSITORY_URL = "https://repo1.maven.org/maven2/";
  private static final int HTTP_TIMEOUT_MS = 5000;
  private static final int MAX_VERSION_SAMPLES = 15;
  private static final int MAX_PARENT_DEPTH = 3;
  private static final int MAX_BOM_DEPTH = 2;
  private static final int MAX_WALK_DEPTH = 4;
  private static final int MAX_FETCHES = 60;
  private static final long DEADLINE_NANOS = TimeUnit.SECONDS.toNanos(10);

  private static final Pattern PROPERTY_PATTERN = Pattern.compile("\\$\\{([^}]+)}");

  private final ConcurrentMap<String, List<String>> versionsCache = new ConcurrentHashMap<>();
  private final ConcurrentMap<String, Optional<MavenPom>> pomCache = new ConcurrentHashMap<>();
  @Nullable private final Path cacheRoot;

  public MavenCentralClient() {
    this(defaultCacheRoot());
  }

  /** Test constructor: a null cache root disables the on-disk POM cache entirely. */
  public MavenCentralClient(@Nullable Path cacheRoot) {
    this.cacheRoot = cacheRoot;
  }

  /** Immutable POM cache root under the IDE system directory, or null when unavailable. */
  @Nullable
  private static Path defaultCacheRoot() {
    try {
      return PathManager.getSystemDir().resolve("vulnspotter").resolve("maven-central");
    } catch (Exception | Error e) {
      return null;
    }
  }

  @Nullable
  private static String cacheFileName(String key) {
    String sanitized = key.replaceAll("[^A-Za-z0-9._-]", "_");
    return sanitized.length() > 200 ? null : sanitized + ".pom";
  }

  private static List<MavenPom.Dependency> relevantDependencies(MavenPom pom) {
    List<MavenPom.Dependency> relevant = new ArrayList<>();
    for (MavenPom.Dependency entry : pom.dependencies()) {
      if (entry.optional() || entry.isBomImport() || "pom".equals(entry.type())) {
        continue;
      }
      relevant.add(entry);
    }
    return relevant;
  }

  /**
   * Substitutes {@code ${property}} references (up to a few nesting rounds) against the given
   * properties; null when a reference stays unresolved.
   */
  private static String substitute(@Nullable String raw, Map<String, String> properties) {
    if (raw == null) {
      return null;
    }
    String substituted = raw.trim();
    for (int round = 0; round < 5 && substituted.contains("${"); round++) {
      Matcher matcher = PROPERTY_PATTERN.matcher(substituted);
      StringBuilder replaced = new StringBuilder();
      boolean unresolved = false;
      while (matcher.find() && !unresolved) {
        String value = properties.get(matcher.group(1));
        if (value == null) {
          unresolved = true;
        } else {
          matcher.appendReplacement(replaced, Matcher.quoteReplacement(value));
        }
      }
      if (unresolved) {
        return null;
      }
      substituted = matcher.appendTail(replaced).toString();
    }
    return substituted;
  }

  /** Plausible single-version text: non-blank, fully substituted, and carrying a digit. */
  private static boolean isPlausibleVersion(@Nullable String version) {
    return version != null
        && !version.isBlank()
        && !version.contains("${")
        && !version.contains(",")
        && version.matches(".*\\d.*");
  }

  private static String repositoryUrl(String group, String artifact, String fileName) {
    return REPOSITORY_URL + group.replace('.', '/') + "/" + artifact + "/" + fileName;
  }

  private static String read(String url) throws IOException {
    return HttpRequests.request(url)
        .connectTimeout(HTTP_TIMEOUT_MS)
        .readTimeout(HTTP_TIMEOUT_MS)
        .readString();
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  /** Whether remediation metadata may be served from or written into the caches. */
  private static boolean cacheEnabled() {
    return !VulnSpotterSettings.getInstance().isDisableVulnerabilityCache();
  }

  @Nullable
  private Optional<MavenPom> readDiskCache(String key) {
    if (cacheRoot == null) {
      return null;
    }
    Path cached = cacheRoot.resolve(cacheFileName(key));
    if (cached == null || !Files.exists(cached)) {
      return null;
    }
    try {
      return MavenPomParser.parsePom(Files.readString(cached));
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  private void writeDiskCache(String key, String xml) {
    String fileName = cacheFileName(key);
    if (cacheRoot == null || fileName == null) {
      return;
    }
    try {
      Files.createDirectories(cacheRoot);
      Files.writeString(cacheRoot.resolve(fileName), xml);
    } catch (IOException e) {
      LOG.info("Maven Central cache write failed for " + key, e);
    }
  }

  /**
   * First parent release for which {@code childVersion >= requiredFix}, walking releases upward.
   */
  public Optional<FixingVersion> fixingVersion(
      String parentGroup,
      String parentArtifact,
      @Nullable String currentVersion,
      String childName,
      String requiredFix) {
    List<String> candidates =
        versions(parentGroup, parentArtifact).stream()
            .filter(version -> !version.isBlank() && !version.endsWith("-SNAPSHOT"))
            .filter(version -> !VersionUtil.isPrerelease(version))
            .filter(version ->
                currentVersion == null || VersionUtil.compareVersions(version, currentVersion) > 0)
            .sorted(VersionUtil::compareVersions)
            .limit(MAX_VERSION_SAMPLES)
            .toList();
    SearchState state = new SearchState();
    for (String candidate : candidates) {
      Optional<String> childVersion =
          childVersionWithin(parentGroup, parentArtifact, candidate, childName, state);
      if (childVersion.isPresent()
          && VersionUtil.compareVersions(childVersion.get(), requiredFix) >= 0) {
        return Optional.of(new FixingVersion(candidate, childVersion.get()));
      }
      if (state.exhausted()) {
        return Optional.empty();
      }
    }
    return Optional.empty();
  }

  /** The release version list of a coordinate from Maven Central; empty on any failure. */
  public List<String> versions(String group, String artifact) {
    String coordinate = group + ":" + artifact;
    boolean cacheable = cacheEnabled();
    List<String> cached = cacheable ? versionsCache.get(coordinate) : null;
    if (cached != null) {
      return cached;
    }
    try {
      String metadata = read(repositoryUrl(group, artifact, "maven-metadata.xml"));
      if (isBlank(metadata)) {
        return List.of();
      }
      List<String> versions = MavenPomParser.parseMetadataVersions(metadata);
      if (cacheable) {
        versionsCache.put(coordinate, versions);
      }
      return versions;
    } catch (IOException e) {
      LOG.info("Maven Central metadata unavailable for " + coordinate, e);
      return List.of();
    }
  }

  /**
   * The child's version inside the candidate parent POM: its management tree or dependency walk.
   */
  private Optional<String> childVersionWithin(
      String parentGroup,
      String parentArtifact,
      String parentVersion,
      String childName,
      SearchState state) {
    Optional<MavenPom> parentPom = pom(parentGroup, parentArtifact, parentVersion, state);
    if (parentPom.isEmpty() || state.exhausted()) {
      return Optional.empty();
    }
    Map<String, String> management = new HashMap<>();
    collectManagement(parentPom.get(), MAX_PARENT_DEPTH, MAX_BOM_DEPTH, management, state);
    String managed = management.get(childName);
    if (isPlausibleVersion(managed)) {
      return Optional.of(managed);
    }
    return findChildInDependencies(parentPom.get(), management, childName, 0, state);
  }

  /**
   * Effective dependency management as Maven resolves it: the parent chain's entries first, then
   * the POM's own entries (which win over the parent's), expanding {@code scope>import} BOM refs up
   * to {@code bomDepth} levels. Versions are substituted against the owning POM's properties;
   * unresolved placeholders leave the entry out.
   */
  private void collectManagement(
      MavenPom pom,
      int parentDepth,
      int bomDepth,
      Map<String, String> management,
      SearchState state) {
    MavenPom.Coordinate parent = pom.parent();
    if (parentDepth > 0 && parent != null) {
      pom(parent.group(), parent.artifact(), parent.version(), state)
          .ifPresent(parentPom ->
              collectManagement(parentPom, parentDepth - 1, bomDepth, management, state));
    }
    for (MavenPom.Dependency entry : pom.managedDependencies()) {
      if (entry.isBomImport()) {
        if (bomDepth <= 0) {
          continue;
        }
        String importVersion = substitute(entry.version(), pom.properties());
        if (!isPlausibleVersion(importVersion)) {
          continue;
        }
        pom(entry.group(), entry.artifact(), importVersion, state)
            .ifPresent(
                bomPom -> collectManagement(bomPom, parentDepth, bomDepth - 1, management, state));
      } else {
        String resolvedVersion = substitute(entry.version(), pom.properties());
        if (isPlausibleVersion(resolvedVersion)) {
          management.put(entry.coordinate(), resolvedVersion);
        }
      }
    }
  }

  /** Shallow walk of the POM's dependency tree for the child, versions from the root management. */
  private Optional<String> findChildInDependencies(
      MavenPom pom,
      Map<String, String> management,
      String childName,
      int depth,
      SearchState state) {
    if (depth >= MAX_WALK_DEPTH || state.exhausted()) {
      return Optional.empty();
    }
    for (MavenPom.Dependency entry : relevantDependencies(pom)) {
      if (entry.coordinate().equals(childName)) {
        String version = substitute(entry.version(), pom.properties());
        if (!isPlausibleVersion(version)) {
          version = management.get(childName);
        }
        if (isPlausibleVersion(version)) {
          return Optional.of(version);
        }
      }
    }
    Map<String, String> declaredProperties = pom.properties();
    for (MavenPom.Dependency entry : relevantDependencies(pom)) {
      if (entry.coordinate().equals(childName)) {
        continue;
      }
      String version = substitute(entry.version(), declaredProperties);
      if (!isPlausibleVersion(version)) {
        version = management.get(entry.coordinate());
      }
      if (!isPlausibleVersion(version)) {
        continue;
      }
      Optional<MavenPom> childPom = pom(entry.group(), entry.artifact(), version, state);
      if (childPom.isEmpty()) {
        continue;
      }
      Optional<String> found =
          findChildInDependencies(childPom.get(), management, childName, depth + 1, state);
      if (found.isPresent()) {
        return found;
      }
    }
    return Optional.empty();
  }

  /** Version lookup against the in-memory cache, the disk cache and Maven Central, in order. */
  private Optional<MavenPom> pom(String group, String artifact, String version, SearchState state) {
    if (group == null || artifact == null || version == null || version.isBlank()) {
      return Optional.empty();
    }
    String key = group + ":" + artifact + ":" + version;
    boolean cacheable = cacheEnabled();
    Optional<MavenPom> cached = cacheable ? pomCache.get(key) : null;
    if (cached == null && cacheable) {
      cached = readDiskCache(key);
    }
    if (cached == null) {
      cached = fetchPom(group, artifact, version, key, state);
      if (cacheable) {
        pomCache.putIfAbsent(key, cached);
      }
    }
    return cached;
  }

  private Optional<MavenPom> fetchPom(
      String group, String artifact, String version, String key, SearchState state) {
    if (state.exhausted()) {
      return Optional.empty();
    }
    state.charge();
    try {
      String xml = read(repositoryUrl(group, artifact, artifact + "-" + version + ".pom"));
      if (isBlank(xml)) {
        return Optional.empty();
      }
      Optional<MavenPom> pom = MavenPomParser.parsePom(xml);
      writeDiskCache(key, xml);
      return pom;
    } catch (IOException e) {
      LOG.info("Maven Central POM unavailable for " + key, e);
      return Optional.empty();
    }
  }

  /** First released parent version that fixes the child, and the child version it ships. */
  public record FixingVersion(String parentVersion, String childVersion) {}

  /** Per-search budget: pom downloads and a hard deadline; the resolver stays read-only on it. */
  private static final class SearchState {

    private final long deadline = System.nanoTime() + DEADLINE_NANOS;
    private int fetches;

    void charge() {
      fetches++;
    }

    boolean exhausted() {
      return fetches >= MAX_FETCHES || System.nanoTime() > deadline;
    }
  }
}
