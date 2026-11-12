/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.toolwindow;

import com.intellij.openapi.Disposable;
import javax.swing.JComponent;

/**
 * Abstraction over the HTML details panel rendering, decoupling the tool window from the concrete
 * engine (JCEF when available, a Swing {@link javax.swing.JEditorPane} fallback otherwise). All
 * JCEF/CEF types are confined to the {@code jcef} submodule: its classes are only visible inside
 * that optional module, loaded when the JCEF plugin is present (see {@code vulnspotter-jcef.xml}).
 */
public interface DetailsPanel extends Disposable {

  /** The Swing component to embed in the tool window splitter. */
  JComponent getComponent();

  /** Replaces the rendered HTML content. */
  void loadHtml(String html);
}
