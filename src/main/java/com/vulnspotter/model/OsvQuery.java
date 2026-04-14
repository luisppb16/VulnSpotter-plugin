/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.vulnspotter.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Represents a query to the OSV API. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OsvQuery(String version, @JsonProperty("package") OsvPackageQuery packageInfo) {
  public OsvQuery {
    Objects.requireNonNull(packageInfo, "Package info cannot be null");
  }

  public OsvQuery(String version, OsvPackage pkg) {
    this(version, new OsvPackageQuery(pkg.name(), pkg.ecosystem()));
  }

  /** Inner record for the specific format OSV API expects for the package field. */
  public record OsvPackageQuery(String name, String ecosystem) {}
}
