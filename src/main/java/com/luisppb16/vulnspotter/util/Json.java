/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

/** Shared immutable Jackson mapper for all OSV parsing and reporting. */
public final class Json {

  public static final ObjectMapper MAPPER = JsonMapper.builder().build();

  private Json() {}
}
