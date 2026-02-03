/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.ui;

import com.intellij.icons.AllIcons;
import com.intellij.ide.BrowserUtil;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Splitter;
import com.intellij.ui.ColorUtil;
import com.intellij.ui.JBColor;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.jcef.JBCefBrowser;
import com.intellij.ui.jcef.JBCefClient;
import com.intellij.ui.table.JBTable;
import com.intellij.util.IconUtil;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.projectsapo.model.OsvVulnerability;
import com.projectsapo.service.VulnerabilityScannerService;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import org.cef.browser.CefBrowser;
import org.cef.browser.CefFrame;
import org.cef.handler.CefRequestHandlerAdapter;
import org.cef.network.CefRequest;

/**
 * Modern UI for Project Sapo using JCEF. Replicates Snyk's design for dependency chains and
 * severity badges.
 */
public class SapoToolWindow {

  private static final String UNKNOWN = "Unknown";
  private static final String CRITICAL = "CRITICAL";
  private static final String HIGH = "HIGH";
  private static final String MEDIUM = "MEDIUM";
  private static final String LOW = "LOW";
  private static final String SAFE = "SAFE";
  private static final String DIV_CLOSE = "</div>";

  private static final Pattern FIXED_VERSION_PATTERN =
      Pattern.compile(
          "Fixed(?:<[^>]+>|\\s){1,100}(\\d+\\.\\d+(?:\\.\\d+)?)", Pattern.CASE_INSENSITIVE);

  private static final JBColor COLOR_CRITICAL = new JBColor(0xB71C1C, 0xB71C1C);
  private static final JBColor COLOR_HIGH = new JBColor(0xE65100, 0xE65100);
  private static final JBColor COLOR_MEDIUM = new JBColor(0xF57F17, 0xF57F17);
  private static final JBColor COLOR_LOW = new JBColor(0x33691E, 0x33691E);

  private final JPanel content;
  private final JBTable resultsTable;
  private final DefaultTableModel tableModel;
  private final JBCefBrowser browser;
  private final Project project;
  private final JButton scanButton;
  private final JLabel statusLabel;
  private final List<VulnerabilityScannerService.ScanResult> scanResults = new ArrayList<>();
  private final NumberFormat numberFormat = NumberFormat.getInstance(Locale.ROOT);

  // Cache for scraped fixed versions: VulnID -> Version
  private final Map<String, String> scrapedVersions = new ConcurrentHashMap<>();
  private final Set<String> scrapingInProgress =
      Collections.newSetFromMap(new ConcurrentHashMap<>());

  public SapoToolWindow(Project project) {
    this.project = project;
    this.content = new JPanel(new BorderLayout());
    this.browser = new JBCefBrowser();

    // Open links in system browser
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

    JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
    scanButton = new JButton("Scan Dependencies");
    scanButton.addActionListener(e -> runScan());
    statusLabel = new JLabel("Ready");
    statusLabel.setBorder(JBUI.Borders.emptyLeft(10));
    toolbar.add(scanButton);
    toolbar.add(statusLabel);
    content.add(toolbar, BorderLayout.NORTH);

    Splitter splitter = new Splitter(false, 0.35f);

    // Updated column name to "Severity"
    tableModel =
        new DefaultTableModel(new String[] {"Severity", "Dependency", "Version", "Vulns"}, 0) {
          @Override
          public boolean isCellEditable(int row, int column) {
            return false;
          }

          @Override
          public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Icon.class;
            if (columnIndex == 3) return Integer.class;
            return String.class;
          }
        };
    resultsTable = new JBTable(tableModel);
    resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    resultsTable.setAutoCreateRowSorter(true); // Enable sorting

    // Set default sort to "Dependency" column (index 1) alphabetically
    TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
    resultsTable.setRowSorter(sorter);
    sorter.setSortKeys(List.of(new RowSorter.SortKey(1, SortOrder.ASCENDING)));

    // Adjust "Severity" column width to fit the header text
    TableColumn iconColumn = resultsTable.getColumnModel().getColumn(0);
    iconColumn.setPreferredWidth(60);
    iconColumn.setMaxWidth(80);
    iconColumn.setMinWidth(60);

    resultsTable
        .getSelectionModel()
        .addListSelectionListener(
            e -> {
              if (!e.getValueIsAdjusting()) {
                int row = resultsTable.getSelectedRow();
                if (row >= 0) {
                  int modelRow = resultsTable.convertRowIndexToModel(row);
                  showDetails(scanResults.get(modelRow));
                }
              }
            });

    splitter.setFirstComponent(new JBScrollPane(resultsTable));
    splitter.setSecondComponent(browser.getComponent());
    content.add(splitter, BorderLayout.CENTER);
    browser.loadHTML(
        generateHtml("<h1>Project Sapo</h1><p>Select a dependency to see details.</p>"));
  }

  private void runScan() {
    scanButton.setEnabled(false);
    statusLabel.setText("Scanning...");
    tableModel.setRowCount(0);
    scanResults.clear();
    scrapedVersions.clear(); // Clear cache on new scan
    scrapingInProgress.clear();

    VulnerabilityScannerService.getInstance(project)
        .scanDependencies()
        .thenAccept(
            results ->
                ApplicationManager.getApplication()
                    .invokeLater(
                        () -> {
                          scanResults.addAll(results);
                          for (VulnerabilityScannerService.ScanResult result : results) {
                            String highestSev = getHighestSeverity(result.vulnerabilities());
                            tableModel.addRow(
                                new Object[] {
                                  getSeverityIcon(highestSev),
                                  result.pkg().name(),
                                  result.pkg().version(),
                                  result.vulnerabilities().size()
                                });
                          }
                          scanButton.setEnabled(true);
                          statusLabel.setText("Scan complete (" + results.size() + ")");
                        }))
        .exceptionally(
            ex -> {
              ApplicationManager.getApplication()
                  .invokeLater(
                      () -> {
                        scanButton.setEnabled(true);
                        statusLabel.setText("Scan failed");
                      });
              return null;
            });
  }

  private void showDetails(VulnerabilityScannerService.ScanResult result) {
    StringBuilder sb = new StringBuilder();
    appendHeader(sb, result);

    if (result.vulnerable()) {
      appendVulnerableDetails(sb, result);
    } else {
      sb.append("<div class='safe-banner'>✅ No known vulnerabilities found.</div>");
    }

    appendDependencyChains(sb, result);

    browser.loadHTML(generateHtml(sb.toString()));
  }

  private void appendHeader(StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    sb.append("<div class='header'>");
    sb.append("<h1>").append(result.pkg().name()).append("</h1>");
    sb.append("<div class='version'>Version: ")
        .append(result.pkg().version())
        .append(DIV_CLOSE);
    sb.append(DIV_CLOSE);
  }

  private void appendVulnerableDetails(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    Set<String> fixedVersions = new HashSet<>();
    for (OsvVulnerability vuln : result.vulnerabilities()) {
      String f = findFixedVersion(vuln, result.pkg().name());
      if (UNKNOWN.equals(f)) {
        if (scrapedVersions.containsKey(vuln.id())) {
          f = scrapedVersions.get(vuln.id());
        } else {
          scrapeFixedVersion(vuln.id(), result);
        }
      }
      if (!UNKNOWN.equals(f)) {
        fixedVersions.add(f);
      }
    }

    boolean hasFix = !fixedVersions.isEmpty();
    String fixedVerStr = hasFix ? String.join(", ", fixedVersions) : UNKNOWN;

    appendRemediation(sb, result, fixedVerStr, hasFix);
    appendVulnerabilities(sb, result);
  }

  private void appendRemediation(
      StringBuilder sb,
      VulnerabilityScannerService.ScanResult result,
      String fixedVerStr,
      boolean hasFix) {
    sb.append("<div class='remediation-box'>");
    sb.append("<div class='remediation-title'>Remediation</div>");

    Set<List<String>> chains = result.pkg().dependencyChains();
    Set<String> roots = new HashSet<>();
    boolean isDirect = isDirectDependency(chains, roots);

    if (isDirect) {
      appendDirectRemediation(sb, result, fixedVerStr, hasFix);
    }

    if (!roots.isEmpty()) {
      if (isDirect) {
        sb.append("<hr style='border: 0; border-top: 1px solid #ccc; margin: 8px 0;'/>");
      }
      appendTransitiveRemediation(sb, result, fixedVerStr, hasFix, roots);
    }
    sb.append(DIV_CLOSE);
  }

  private boolean isDirectDependency(Set<List<String>> chains, Set<String> roots) {
    boolean isDirect = false;
    if (chains != null && !chains.isEmpty()) {
      for (List<String> chain : chains) {
        if (chain.size() <= 1) {
          isDirect = true;
        } else {
          roots.add(chain.getFirst());
        }
      }
    } else {
      isDirect = true;
    }
    return isDirect;
  }

  private void appendDirectRemediation(
      StringBuilder sb,
      VulnerabilityScannerService.ScanResult result,
      String fixedVerStr,
      boolean hasFix) {
    if (hasFix) {
      sb.append("<p>Upgrade <b>")
          .append(result.pkg().name())
          .append("</b> to version <b>")
          .append(fixedVerStr)
          .append("</b></p>");
    } else {
      sb.append("<p>No fixed version available for <b>")
          .append(result.pkg().name())
          .append("</b> at this time.</p>");
      sb.append("<p style='font-size: 11px; color: #888; margin-top: 4px;'>")
          .append("Checking online sources...")
          .append("</p>");
    }
  }

  private void appendTransitiveRemediation(
      StringBuilder sb,
      VulnerabilityScannerService.ScanResult result,
      String fixedVerStr,
      boolean hasFix,
      Set<String> roots) {
    if (hasFix) {
      sb.append("<p>For transitive dependencies, upgrade:</p>");
      sb.append("<ul>");
      for (String root : roots) {
        sb.append("<li><code>").append(root).append("</code></li>");
      }
      sb.append("</ul>");
      sb.append("<p>to a version that uses <b>")
          .append(result.pkg().name())
          .append("</b> version <b>")
          .append(fixedVerStr)
          .append("</b>.</p>");
    } else {
      sb.append("<p>Transitive dependency <b>")
          .append(result.pkg().name())
          .append("</b> has no fixed version available.</p>");
      sb.append("<p>Affected roots:</p><ul>");
      for (String root : roots) {
        sb.append("<li><code>").append(root).append("</code></li>");
      }
      sb.append("</ul>");
    }
  }

  private void appendVulnerabilities(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    sb.append("<div class='section-title'>")
        .append(result.vulnerabilities().size())
        .append(" Vulnerabilities</div>");
    for (OsvVulnerability vuln : result.vulnerabilities()) {
      String sev = getSeverity(vuln);
      String fixedV = findFixedVersion(vuln, result.pkg().name());
      if (UNKNOWN.equals(fixedV) && scrapedVersions.containsKey(vuln.id())) {
        fixedV = scrapedVersions.get(vuln.id());
      }

      sb.append("<div class='card'>");
      sb.append("<div class='card-header'>");
      sb.append("<span class='badge ")
          .append(sev.toLowerCase())
          .append("'>")
          .append(sev)
          .append("</span>");
      sb.append("<span class='vuln-id'><a href='https://osv.dev/vulnerability/")
          .append(vuln.id())
          .append("'>")
          .append(vuln.id())
          .append("</a></span>");
      sb.append(DIV_CLOSE);
      sb.append("<div class='vuln-summary'>")
          .append(vuln.summary() != null ? vuln.summary() : "No summary")
          .append(DIV_CLOSE);
      sb.append("<div class='fixed-box'>Fixed in: <span class='fixed-ver'>")
          .append(fixedV)
          .append("</span></div>");
      sb.append("<div class='details'>")
          .append(vuln.details() != null ? vuln.details().replace("\n", "<br>") : "")
          .append(DIV_CLOSE);

      if (vuln.references() != null && !vuln.references().isEmpty()) {
        sb.append("<div class='references-section'>");
        sb.append("<div class='references-title'>References</div>");
        for (OsvVulnerability.Reference ref : vuln.references()) {
          sb.append("<div class='reference-item'><a href='")
              .append(ref.url())
              .append("'>")
              .append(ref.url())
              .append("</a></div>");
        }
        sb.append(DIV_CLOSE);
      }
      sb.append(DIV_CLOSE);
    }
  }

  private void appendDependencyChains(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    Set<List<String>> chains = result.pkg().dependencyChains();
    if (chains != null && !chains.isEmpty()) {
      int pathIndex = 1;
      for (List<String> chain : chains) {
        if (chains.size() > 1) {
          sb.append("<div class='path-header'>Path #").append(pathIndex++).append(DIV_CLOSE);
        }
        sb.append("<div class='snyk-chain'>");

        // Root
        sb.append("<div class='chain-item root'><span class='icon'>📦</span> ")
            .append(project.getName())
            .append(DIV_CLOSE);

        // Intermediate
        for (int i = 0; i < chain.size() - 1; i++) {
          sb.append("<div class='chain-item intermediate' style='padding-left: ")
              .append((i + 1) * 20)
              .append("px;'>");
          sb.append("<span class='connector'>└─</span> <span class='icon'>📄</span> ")
              .append(chain.get(i));
          sb.append(DIV_CLOSE);
        }

        // Target (Vulnerable)
        String target = chain.getLast();
        sb.append("<div class='chain-item target' style='padding-left: ")
            .append(chain.size() * 20)
            .append("px;'>");
        sb.append("<span class='connector'>└─</span> <span class='icon'>⚠️</span> <b>")
            .append(target)
            .append("</b>");
        sb.append(DIV_CLOSE);

        sb.append(DIV_CLOSE); // End snyk-chain
      }
    }
  }

  private void scrapeFixedVersion(String vulnId, VulnerabilityScannerService.ScanResult result) {
    if (!scrapingInProgress.add(vulnId)) return;

    ApplicationManager.getApplication()
        .executeOnPooledThread(
            () -> {
              try {
                URL url = new URI("https://osv.dev/vulnerability/" + vulnId).toURL();
                String html;
                try (InputStream in = url.openStream()) {
                  html = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                }

                // Regex to find "Fixed" followed by a version number in the HTML
                // Matches "Fixed" followed by tags/spaces and then a version number
                // Simplified regex to avoid stack overflow warning
                Matcher m = FIXED_VERSION_PATTERN.matcher(html);
                if (m.find()) {
                  String ver = m.group(1);
                  scrapedVersions.put(vulnId, ver);

                  // Refresh UI if the currently selected item is still the same
                  ApplicationManager.getApplication()
                      .invokeLater(
                          () -> {
                            int selectedRow = resultsTable.getSelectedRow();
                            if (selectedRow >= 0) {
                              int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
                              if (modelRow < scanResults.size()
                                  && scanResults.get(modelRow).equals(result)) {
                                showDetails(result);
                              }
                            }
                          });
                }
              } catch (IOException | URISyntaxException e) {
                // Ignore scraping errors
              } finally {
                scrapingInProgress.remove(vulnId);
              }
            });
  }

  private String generateHtml(String bodyContent) {
    boolean isDark = ColorUtil.isDark(UIUtil.getPanelBackground());
    String bgColor = isDark ? "#1e1e1e" : "#ffffff";
    String textColor = isDark ? "#d4d4d4" : "#333333";
    String cardBg = isDark ? "#252526" : "#ffffff";
    String borderColor = isDark ? "#454545" : "#e0e0e0";

    return "<html><head><style>"
        + "body { font-family: 'Inter', sans-serif; padding: 24px; background: "
        + bgColor
        + "; color: "
        + textColor
        + "; line-height: 1.5; }"
        + "h1 { font-size: 20px; font-weight: 600; margin: 0; }"
        + ".version { color: #888; margin-top: 4px; margin-bottom: 16px; font-size: 13px; }"
        + ".section-title { font-weight: bold; margin-top: 16px; margin-bottom: 8px; font-size: 14px; }"
        + ".safe-banner { background: rgba(67, 160, 71, 0.1); color: #2e7d32; padding: 12px; border-radius: 4px; font-weight: 600; margin-top: 16px; margin-bottom: 16px; }"
        + ".path-header { font-weight: bold; margin-top: 12px; margin-bottom: 4px; color: #2196f3; font-size: 14px; }"
        + ".snyk-chain { font-family: 'JetBrains Mono', monospace; margin: 8px 0; font-size: 13px; }"
        + ".chain-item { padding: 4px 0; display: flex; align-items: center; }"
        + ".connector { color: #888; margin-right: 8px; }"
        + ".icon { margin-right: 6px; }"
        + ".target { color: #e53935; font-weight: bold; }"
        + ".remediation-box { background: "
        + (isDark ? "#1a2a3a" : "#e3f2fd")
        + "; border: 1px solid #2196f3; border-radius: 4px; padding: 12px; margin-top: 8px; margin-bottom: 16px; }"
        + ".remediation-title { font-weight: 800; color: #2196f3; text-transform: uppercase; font-size: 11px; margin-bottom: 4px; }"
        + ".card { background: "
        + cardBg
        + "; border: 1px solid "
        + borderColor
        + "; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }"
        + ".badge { padding: 4px 8px; border-radius: 4px; color: white; font-size: 11px; font-weight: 800; margin-right: 12px; text-transform: uppercase; }"
        + ".critical { background: #b71c1c; } .high { background: #e65100; } .medium { background: #f57f17; color: white; } .low { background: #33691e; }"
        + ".fixed-box { background: rgba(67, 160, 71, 0.1); color: #2e7d32; padding: 4px 8px; border-radius: 4px; font-weight: 600; display: inline-block; margin: 8px 0; }"
        + ".references-section { margin-top: 16px; border-top: 1px solid "
        + borderColor
        + "; padding-top: 12px; }"
        + ".references-title { font-weight: 800; color: #888; text-transform: uppercase; font-size: 10px; margin-bottom: 8px; }"
        + ".reference-item { font-size: 12px; margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }"
        + "a { color: #2196f3; text-decoration: none; } a:hover { text-decoration: underline; }"
        + "</style></head><body>"
        + bodyContent
        + "</body></html>";
  }

  private String getHighestSeverity(List<OsvVulnerability> vulns) {
    if (vulns.isEmpty()) return SAFE;
    int max = 0;
    for (OsvVulnerability v : vulns) {
      int l =
          switch (getSeverity(v)) {
            case CRITICAL -> 4;
            case HIGH -> 3;
            case MEDIUM -> 2;
            case LOW -> 1;
            default -> 0;
          };
      if (l > max) max = l;
    }
    return switch (max) {
      case 4 -> CRITICAL;
      case 3 -> HIGH;
      case 2 -> MEDIUM;
      case 1 -> LOW;
      default -> SAFE;
    };
  }

  private Icon getSeverityIcon(String s) {
    return switch (s) {
      case CRITICAL -> IconUtil.colorize(AllIcons.General.Error, COLOR_CRITICAL);
      case HIGH -> IconUtil.colorize(AllIcons.General.Warning, COLOR_HIGH);
      case MEDIUM -> IconUtil.colorize(AllIcons.General.Note, COLOR_MEDIUM);
      case LOW -> IconUtil.colorize(AllIcons.General.Information, COLOR_LOW);
      default -> IconUtil.colorize(AllIcons.General.InspectionsOK, COLOR_LOW);
    };
  }

  private String getSeverity(OsvVulnerability v) {
    String dbSeverity = getSeverityFromDatabaseSpecific(v);
    if (dbSeverity != null) {
      return dbSeverity;
    }
    return getSeverityFromCvss(v);
  }

  private String getSeverityFromDatabaseSpecific(OsvVulnerability v) {
    if (v.databaseSpecific() != null) {
      Object sev = v.databaseSpecific().get("severity");
      if (sev instanceof String string) {
        return string.toUpperCase();
      }
    }
    return null;
  }

  private String getSeverityFromCvss(OsvVulnerability v) {
    if (v.severity() == null) {
      return MEDIUM;
    }
    return v.severity().stream()
        .filter(s -> "CVSS_V3".equals(s.type()) || "CVSS_V2".equals(s.type()))
        .map(this::parseScore)
        .filter(Objects::nonNull)
        .findFirst()
        .map(this::getSeverityLevel)
        .orElse(MEDIUM);
  }

  private Double parseScore(OsvVulnerability.Severity s) {
    try {
      return numberFormat.parse(s.score()).doubleValue();
    } catch (ParseException | NumberFormatException e) {
      return null;
    }
  }

  private String getSeverityLevel(double score) {
    if (score >= 9.0) return CRITICAL;
    if (score >= 7.0) return HIGH;
    if (score >= 4.0) return MEDIUM;
    return LOW;
  }

  private String findFixedVersion(OsvVulnerability v, String pkgName) {
    if (v.affected() == null) return UNKNOWN;
    return v.affected().stream()
        .filter(a -> a.pkg() == null || pkgName.equals(a.pkg().name()))
        .filter(a -> a.ranges() != null)
        .flatMap(a -> a.ranges().stream())
        .filter(r -> r.events() != null)
        .flatMap(r -> r.events().stream())
        .map(OsvVulnerability.Event::fixed)
        .filter(Objects::nonNull)
        .findFirst()
        .orElse(UNKNOWN);
  }

  public JComponent getContent() {
    return content;
  }
}
