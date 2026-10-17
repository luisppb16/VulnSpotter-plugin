/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.toolwindow;

import com.intellij.ide.BrowserUtil;
import com.intellij.ui.components.JBScrollPane;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.event.HyperlinkEvent;

/**
 * Swing-only {@link DetailsPanel} backed by a {@link JEditorPane} rendering limited HTML. Always
 * loadable (no JCEF dependency); used when the JCEF plugin is absent or unsupported. Links are
 * delegated to the system browser via {@link BrowserUtil}.
 */
final class SwingDetailsPanel implements DetailsPanel {

  private final JEditorPane pane = new JEditorPane();
  private final JBScrollPane scrollPane = new JBScrollPane(pane);

  SwingDetailsPanel() {
    pane.setContentType("text/html");
    pane.setEditable(false);
    pane.addHyperlinkListener(
        e -> {
          if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED && e.getURL() != null) {
            BrowserUtil.browse(e.getURL());
          }
        });
  }

  @Override
  public JComponent getComponent() {
    return scrollPane;
  }

  @Override
  public void loadHtml(String html) {
    pane.setText(html);
    pane.setCaretPosition(0);
  }

  @Override
  public void dispose() {
    // Nothing to dispose: JEditorPane has no native resources.
  }
}
