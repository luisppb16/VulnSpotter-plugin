/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.projectsapo.util;

/**
 * Constants used throughout the Project Sapo application. Contains API URLs, configuration keys,
 * and other hardcoded values.
 */
public final class ProjectConstants {

  /** The URL for the OSV.dev API. */
  public static final String OSV_API_URL = "https://api.osv.dev/v1/query";

  /** The URL for the OSV.dev API Batch Endpoint. */
  public static final String OSV_API_BATCH_URL = "https://api.osv.dev/v1/querybatch";

  /** Private constructor to prevent instantiation. */
  private ProjectConstants() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }
}
