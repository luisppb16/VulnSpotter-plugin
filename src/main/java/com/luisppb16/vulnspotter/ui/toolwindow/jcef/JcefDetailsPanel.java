/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.toolwindow.jcef;

import com.intellij.ide.BrowserUtil;
import com.intellij.openapi.util.Disposer;
import com.intellij.ui.jcef.JBCefBrowser;
import com.intellij.ui.jcef.JBCefClient;
import com.intellij.util.net.ProxySettings;
import com.luisppb16.vulnspotter.ui.toolwindow.DetailsPanel;
import javax.swing.JComponent;
import org.cef.browser.CefBrowser;
import org.cef.browser.CefFrame;
import org.cef.handler.CefRequestHandlerAdapter;
import org.cef.network.CefRequest;

/**
 * JCEF-backed {@link DetailsPanel}. This class is the only place that references {@code
 * com.intellij.ui.jcef.*} and {@code org.cef.*}, so it is only loaded when the optional JCEF module
 * (see {@code vulnspotter-jcef.xml}) is present, preventing {@code NoClassDefFoundError} on IDEs
 * without the JCEF plugin. It is registered via {@link JcefDetailsPanelFactory}, which additionally
 * guards instantiation with {@link com.intellij.ui.jcef.JBCefApp#isSupported()}.
 */
final class JcefDetailsPanel implements DetailsPanel {

  private final JBCefBrowser browser;

  JcefDetailsPanel() {
    // JBCefApp's <clinit> resolves proxy settings through HttpConfigurable — directly via
    // JBCefProxySettings in 2026.2, via the public ProxySettings/ProxyCredentialStore model in
    // 2026.3. The first creation of HttpConfigurable requests ProxyMigrationService, and the
    // platform rejects that nested service lookup from <clinit> ("Class initialization must not
    // depend on services"). Resolving the public ProxySettings here, outside any class
    // initializer, creates HttpConfigurable, so the <clinit> only performs cached lookups.
    ProxySettings.getInstance().getProxyConfiguration();
    this.browser = new JBCefBrowser();
    Disposer.register(this, browser);

    // Open links (user gestures) in the system browser instead of navigating inside the panel.
    JBCefClient client = this.browser.getJBCefClient();
    if (client != null) {
      client.addRequestHandler(
          new CefRequestHandlerAdapter() {
            @Override
            public boolean onBeforeBrowse(
                CefBrowser browser,
                CefFrame frame,
                CefRequest request,
                boolean userGesture,
                boolean isRedirect) {
              if (userGesture) {
                BrowserUtil.browse(request.getURL());
                return true;
              }
              return false;
            }
          },
          this.browser.getCefBrowser());
    }
  }

  @Override
  public JComponent getComponent() {
    return browser.getComponent();
  }

  @Override
  public void loadHtml(String html) {
    browser.loadHTML(html);
  }

  @Override
  public void dispose() {
    // browser is registered as a child of this Disposable, so it is disposed automatically.
  }
}
