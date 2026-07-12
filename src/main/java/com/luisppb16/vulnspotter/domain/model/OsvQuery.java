/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Represents a query to the OSV API. */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OsvQuery(
    String version,
    @JsonProperty("package") OsvPackageQuery packageInfo,
    @JsonProperty("page_token") String pageToken) {
  public OsvQuery {
    Objects.requireNonNull(packageInfo, "Package info cannot be null");
  }

  public OsvQuery(String version, OsvPackageQuery packageInfo) {
    this(version, packageInfo, null);
  }

  public OsvQuery(String version, OsvPackage pkg) {
    this(version, new OsvPackageQuery(pkg.name(), pkg.ecosystem()), null);
  }

  /** Returns a copy of this query targeting the given results page. */
  public OsvQuery withPageToken(String token) {
    return new OsvQuery(version, packageInfo, token);
  }

  /** Inner record for the specific format OSV API expects for the package field. */
  public record OsvPackageQuery(String name, String ecosystem) {}
}
