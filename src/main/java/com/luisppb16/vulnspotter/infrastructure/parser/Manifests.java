/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.parser;

/**
 * Manifest files VulnSpotter operates on. The supported set must live here and nowhere else, so
 * that extending it (e.g. {@code build.gradle.kts}) keeps scanning, highlighting, quick-fix and
 * export consistent. The ecosystem → manifest-file mapping lives in {@code domain/model/Ecosystem}.
 */
public final class Manifests {

  public static final String POM_XML = "pom.xml";
  public static final String BUILD_GRADLE = "build.gradle";

  private Manifests() {
    throw new UnsupportedOperationException("Utility class");
  }

  /** True when a file is a manifest the plugin parses and annotates. */
  public static boolean isSupported(String fileName) {
    return POM_XML.equals(fileName) || BUILD_GRADLE.equals(fileName);
  }
}
