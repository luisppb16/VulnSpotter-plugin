/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.maven;

import java.util.List;
import java.util.Map;
import org.jetbrains.annotations.Nullable;

/**
 * The parts of a published Maven POM the transitive-remediation resolver reads: its parent
 * coordinate, its properties, the entries of its {@code <dependencyManagement>} and its declared
 * {@code <dependencies>}. Versions keep the raw POM text (possible {@code ${property}} included);
 * substitution happens at resolution time against the owning POM's properties.
 */
public record MavenPom(
    @Nullable Coordinate parent,
    Map<String, String> properties,
    List<Dependency> managedDependencies,
    List<Dependency> dependencies) {

  /** Maven coordinate of a POM's parent: version is always present for a {@code <parent>}. */
  public record Coordinate(String group, String artifact, @Nullable String version) {

    public String coordinate() {
      return group + ":" + artifact;
    }
  }

  /**
   * One {@code <dependency>}, either under {@code <dependencyManagement>} or {@code
   * <dependencies>}.
   */
  public record Dependency(
      String group,
      String artifact,
      @Nullable String version,
      @Nullable String type,
      @Nullable String scope,
      boolean optional) {

    public String coordinate() {
      return group + ":" + artifact;
    }

    /** True for the {@code <type>pom</type><scope>import</scope>} entries that pull a BOM in. */
    public boolean isBomImport() {
      return "pom".equals(type) && "import".equals(scope);
    }
  }
}
