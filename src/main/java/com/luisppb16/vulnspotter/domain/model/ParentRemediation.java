/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.model;

import org.jetbrains.annotations.Nullable;

/**
 * Upgrade suggestion for one transitive root of a scanned package: the declared dependency ({@code
 * root}) that currently pulls the vulnerable artifact in, the version it ships today and — when
 * Maven Central metadata made it deducible — the first released version of that root ({@code
 * targetVersion}) that bundles the package at {@code shipsChildVersion}, at or above the required
 * fix. Null {@code targetVersion} keeps the generic "upgrade the root" phrasing.
 */
public record ParentRemediation(
    String root,
    @Nullable String currentVersion,
    @Nullable String targetVersion,
    @Nullable String shipsChildVersion) {

  /** Display text for the root, annotated with its resolved version when known. */
  public String rootWithVersion() {
    return currentVersion == null ? root : root + " " + currentVersion;
  }
}
