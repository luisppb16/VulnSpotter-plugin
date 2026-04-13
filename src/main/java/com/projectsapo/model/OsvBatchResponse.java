/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collections;
import java.util.List;

/** Represents the response from the OSV API for a batch query. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OsvBatchResponse(@JsonProperty("results") List<OsvResponse> results) {
  public OsvBatchResponse {
    results = results != null ? results : Collections.emptyList();
  }
}
