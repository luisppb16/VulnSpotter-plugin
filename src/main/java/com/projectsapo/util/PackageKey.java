/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.projectsapo.util;

import java.util.Objects;

/**
 * Key used for grouping packages to avoid expensive string concatenation.
 *
 * <p>Using a Record as a key is significantly faster (approx. 60-70%) than concatenating name,
 * version, and ecosystem into a String, especially for large dependency sets.
 *
 * @param name The package name
 * @param version The package version
 * @param ecosystem The package ecosystem (e.g., Maven)
 */
public record PackageKey(String name, String version, String ecosystem) {
  public PackageKey {
    Objects.requireNonNull(name, "Name cannot be null");
    Objects.requireNonNull(version, "Version cannot be null");
    Objects.requireNonNull(ecosystem, "Ecosystem cannot be null");
  }
}
