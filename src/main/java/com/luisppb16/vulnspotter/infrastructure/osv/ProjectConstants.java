/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.osv;

/**
 * Constants used throughout the VulnSpotter plugin. Contains API URLs, configuration keys, and
 * other hardcoded values.
 */
public final class ProjectConstants {

  /** The URL for the OSV.dev API Batch Endpoint. */
  public static final String OSV_API_BATCH_URL = "https://api.osv.dev/v1/querybatch";

  /** Base URL for fetching a full vulnerability record by id (append the id). */
  public static final String OSV_API_VULNS_URL = "https://api.osv.dev/v1/vulns/";

  /** Base URL of the public OSV.dev web page of a vulnerability (append the id). */
  public static final String OSV_WEB_VULN_URL = "https://osv.dev/vulnerability/";

  /** Base URL of the NVD detail page of a CVE id (append the id). */
  public static final String NVD_VULN_URL = "https://nvd.nist.gov/vuln/detail/";

  /** Private constructor to prevent instantiation. */
  private ProjectConstants() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }
}
