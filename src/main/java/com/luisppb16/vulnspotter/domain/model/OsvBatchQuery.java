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
import java.util.Objects;

/** Represents a batch query to the OSV API. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OsvBatchQuery(@JsonProperty("queries") List<OsvQuery> queries) {
  public OsvBatchQuery {
    Objects.requireNonNull(queries, "Queries list cannot be null");
  }
}
