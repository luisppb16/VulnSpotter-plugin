/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.VulnSpotter.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * Represents the response from the OSV API.
 *
 * @param vulns A list of vulnerabilities found for the queried package.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OsvResponse(List<OsvVulnerability> vulns) {}
