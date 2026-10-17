/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.parser;

import com.luisppb16.vulnspotter.domain.model.Ecosystem;

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

  /**
   * Ecosystem id to match packages parsed from an annotated manifest. Every supported manifest is a
   * Maven one today (Gradle libraries are resolved against Maven coordinates too); keeping the
   * inverse mapping next to {@link #isSupported} means extending the set also updates the ecosystem
   * the annotator matches on, in one place.
   */
  public static String ecosystemOf(String fileName) {
    if (!isSupported(fileName)) {
      throw new IllegalArgumentException("Unsupported manifest: " + fileName);
    }
    return Ecosystem.MAVEN;
  }
}
