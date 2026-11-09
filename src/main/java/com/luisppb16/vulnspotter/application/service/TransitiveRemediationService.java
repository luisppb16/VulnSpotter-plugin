/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.application.service;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.Service;
import com.luisppb16.vulnspotter.domain.model.DependencyProvenance;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.domain.model.ParentRemediation;
import com.luisppb16.vulnspotter.domain.service.FixedVersionResolver;
import com.luisppb16.vulnspotter.infrastructure.maven.MavenCentralClient;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jetbrains.annotations.Nullable;

/**
 * Turns a scanned transitive dependency into per-root upgrade suggestions: which declared
 * dependency currently pulls the vulnerable package in (with the version the scan resolved for it)
 * and — best effort via Maven Central metadata — the first released version of that parent which
 * already ships the package at or above the required fix. Calls must run off the EDT; they block on
 * network for a bounded time and always degrade to the scan-only answer.
 */
@Service(Service.Level.APP)
public final class TransitiveRemediationService {

  private final MavenCentralClient client;

  @SuppressWarnings("unused")
  public TransitiveRemediationService() {
    this(new MavenCentralClient());
  }

  TransitiveRemediationService(MavenCentralClient client) {
    this.client = client;
  }

  /** The application-wide instance the report builders and the tool window share. */
  public static TransitiveRemediationService getInstance() {
    return ApplicationManager.getApplication().getService(TransitiveRemediationService.class);
  }

  /**
   * One {@link ParentRemediation} per distinct transitive root of {@code pkg}. The root's current
   * version comes from {@code versionIndex}; the fixing parent version is deduced only when Maven
   * Central metadata allows it. An unknown {@code requiredFix} yields no remediations.
   */
  public List<ParentRemediation> resolve(
      OsvPackage pkg, @Nullable String requiredFix, Map<String, String> versionIndex) {
    if (pkg == null || requiredFix == null || FixedVersionResolver.UNKNOWN.equals(requiredFix)) {
      return List.of();
    }
    DependencyProvenance provenance = DependencyProvenance.of(pkg.dependencyChains());
    if (!provenance.known() || provenance.transitiveRoots().isEmpty()) {
      return List.of();
    }
    Map<String, String> versions = versionIndex == null ? Map.of() : versionIndex;
    return provenance.transitiveRoots().stream()
        .filter(root -> !DependencyProvenance.isPlatformRoot(root))
        .map(root -> resolveRoot(root, pkg.name(), requiredFix, versions))
        .toList();
  }

  private ParentRemediation resolveRoot(
      String root, String childName, String requiredFix, Map<String, String> versionIndex) {
    String currentVersion = versionIndex.get(root);
    int separator = root.indexOf(':');
    if (separator <= 0 || separator == root.length() - 1) {
      return new ParentRemediation(root, currentVersion, null, null);
    }
    Optional<MavenCentralClient.FixingVersion> target =
        client.fixingVersion(
            root.substring(0, separator),
            root.substring(separator + 1),
            currentVersion,
            childName,
            requiredFix);
    return new ParentRemediation(
        root,
        currentVersion,
        target.map(MavenCentralClient.FixingVersion::parentVersion).orElse(null),
        target.map(MavenCentralClient.FixingVersion::childVersion).orElse(null));
  }
}
