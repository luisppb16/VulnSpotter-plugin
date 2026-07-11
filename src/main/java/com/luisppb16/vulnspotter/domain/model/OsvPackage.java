/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Represents the package information. Includes the dependency chain to show how a transitive
 * dependency reached the project.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OsvPackage(
    String name, String ecosystem, String version, Set<List<String>> dependencyChains) {
  public OsvPackage {
    Objects.requireNonNull(name, "Package name cannot be null");
    Objects.requireNonNull(version, "Version cannot be null");
    Objects.requireNonNull(ecosystem, "Ecosystem cannot be null");
    dependencyChains = dependencyChains != null ? Set.copyOf(dependencyChains) : Set.of();
  }

  // Constructor de conveniencia para compatibilidad
  public OsvPackage(String name, String ecosystem, String version) {
    this(name, ecosystem, version, Set.of());
  }
}
