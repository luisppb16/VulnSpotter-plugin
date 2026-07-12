/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Represents the response from the OSV API.
 *
 * @param vulns A list of vulnerabilities found for the queried package.
 * @param nextPageToken Present when the result set is paginated and more results are available.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OsvResponse(
    List<OsvVulnerability> vulns, @JsonProperty("next_page_token") String nextPageToken) {

  /** Convenience constructor kept for backwards compatibility with existing callers/tests. */
  public OsvResponse(List<OsvVulnerability> vulns) {
    this(vulns, null);
  }
}
