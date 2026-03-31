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
import com.intellij.ui.DocumentAdapter;
import com.intellij.ui.JBColor;
import com.intellij.ui.SearchTextField;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.jcef.JBCefBrowser;
import com.intellij.ui.jcef.JBCefClient;
import com.intellij.ui.table.JBTable;
import com.intellij.util.IconUtil;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.projectsapo.model.OsvVulnerability;
import com.projectsapo.report.ReportExportService;
import com.projectsapo.report.VulnerabilityReportBuilder;
import com.projectsapo.service.VulnerabilityScannerService;
import com.projectsapo.util.HtmlEscaper;
import com.projectsapo.util.SeverityAnalyzer;
import com.projectsapo.util.VersionUtil;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
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
public final class SapoToolWindow {

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
  private static final long EXPORT_WAIT_TIMEOUT_MS = 8000;
  private static final int SCRAPE_CONNECT_TIMEOUT_MS = 4000;
  private static final int SCRAPE_READ_TIMEOUT_MS = 6000;
  private final JPanel content;
  private final CardLayout cardLayout = new CardLayout();
  private final JPanel mainPanel;
  private final JBTable resultsTable;
  private final DefaultTableModel tableModel;
  private final JBCefBrowser browser;
  private final Project project;
  private final JButton scanButton;
  private final JButton exportHtmlButton;
  private final JButton exportPdfButton;
  private final JButton exportCsvButton;
  private final JLabel statusLabel;
  private final SearchTextField searchField;
  private final JBCheckBox vulnerableOnlyCheckbox;
  private final JProgressBar progressBar;
  private final List<VulnerabilityScannerService.ScanResult> scanResults = new ArrayList<>();
  private final SeverityAnalyzer severityAnalyzer = new SeverityAnalyzer();

  // Cache for scraped fixed versions: VulnID -> Version
  
  private final Set<String> scrapingInProgress =
      Collections.newSetFromMap(new ConcurrentHashMap<>());
  private java.util.concurrent.CountDownLatch scrapingLatch;

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

    JPanel toolbar = new JPanel(new BorderLayout());
    toolbar.setBorder(JBUI.Borders.empty(4, 8));

    JPanel leftActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
    scanButton = new JButton("Scan Dependencies", AllIcons.Actions.Execute);
    scanButton.addActionListener(e -> runScan());
    leftActions.add(scanButton);

    vulnerableOnlyCheckbox = new JBCheckBox("Vulnerable only", true);
    vulnerableOnlyCheckbox.addActionListener(e -> applyFilters());
    leftActions.add(vulnerableOnlyCheckbox);

    exportHtmlButton = new JButton("Export HTML");
    exportHtmlButton.setEnabled(false);
    exportHtmlButton.addActionListener(e -> exportReport("html"));
    leftActions.add(exportHtmlButton);

    exportPdfButton = new JButton("Export PDF");
    exportPdfButton.setEnabled(false);
    exportPdfButton.addActionListener(e -> exportReport("pdf"));
    leftActions.add(exportPdfButton);

    exportCsvButton = new JButton("Export CSV");
    exportCsvButton.setEnabled(false);
    exportCsvButton.addActionListener(e -> exportReport("csv"));
    leftActions.add(exportCsvButton);

    statusLabel = new JLabel("Ready");
    leftActions.add(statusLabel);

    progressBar = new JProgressBar();
    progressBar.setIndeterminate(true);
    progressBar.setVisible(false);
    progressBar.setPreferredSize(new Dimension(100, 16));
    leftActions.add(progressBar);

    // Removed exportHtmlButton.addActionListener(e -> exportReport(false)) from original logic since we have changed it to format string
    exportHtmlButton.removeActionListener(exportHtmlButton.getActionListeners()[0]);
    exportHtmlButton.addActionListener(e -> exportReport("html"));

    searchField = new SearchTextField();
    searchField.addDocumentListener(
        new DocumentAdapter() {
          @Override
          protected void textChanged(javax.swing.event.DocumentEvent e) {
            applyFilters();
          }
        });
    searchField.setPreferredSize(new Dimension(250, 30));
    searchField.setMinimumSize(new Dimension(250, 30));
    searchField.setMaximumSize(new Dimension(250, 30));

    toolbar.add(leftActions, BorderLayout.WEST);
    content.add(toolbar, BorderLayout.NORTH);

    Splitter splitter = new Splitter(false, 0.35f);

    // Updated column name to "Severity"
    tableModel =
        new DefaultTableModel(
            new String[] {"Severity", "Dependency", "Version", "Fixed In", "Vulns"}, 0) {
          @Override
          public boolean isCellEditable(int row, int column) {
            return false;
          }

          @Override
          public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Icon.class;
            if (columnIndex == 4) return Integer.class;
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

    TableColumn vulnsColumn = resultsTable.getColumnModel().getColumn(4);
    vulnsColumn.setPreferredWidth(50);
    vulnsColumn.setMaxWidth(70);
    vulnsColumn.setMinWidth(40);

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

    JPanel leftPanel = new JPanel(new BorderLayout());
    JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 5));
    searchPanel.setBorder(JBUI.Borders.empty(0, 5, 5, 0));
    searchPanel.add(searchField);
    leftPanel.add(searchPanel, BorderLayout.NORTH);
    leftPanel.add(new JBScrollPane(resultsTable), BorderLayout.CENTER);

    splitter.setFirstComponent(leftPanel);
    splitter.setSecondComponent(browser.getComponent());

    mainPanel = new JPanel(cardLayout);
    mainPanel.add(createEmptyStatePanel(), "EMPTY");
    mainPanel.add(splitter, "RESULTS");

    content.add(mainPanel, BorderLayout.CENTER);
    cardLayout.show(mainPanel, "EMPTY");

    browser.loadHTML(
        generateHtml("<h1>Project Sapo</h1><p>Select a dependency to see details.</p>"));
  }

  private JPanel createEmptyStatePanel() {
    JPanel panel = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 0;
    gbc.insets = JBUI.insets(10);

    JLabel iconLabel = new JLabel(IconUtil.toSize(AllIcons.General.Warning, 64, 64));
    panel.add(iconLabel, gbc);

    gbc.gridy++;
    JLabel titleLabel = new JLabel("No dependencies scanned yet");
    titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
    panel.add(titleLabel, gbc);

    gbc.gridy++;
    JLabel descLabel =
        new JLabel("Scan your project to detect security vulnerabilities in your dependencies.");
    descLabel.setForeground(UIUtil.getContextHelpForeground());
    panel.add(descLabel, gbc);

    gbc.gridy++;
    JButton bigScanButton = new JButton("Scan Project Dependencies", AllIcons.Actions.Execute);
    bigScanButton.addActionListener(e -> runScan());
    panel.add(bigScanButton, gbc);

    return panel;
  }

  private void applyFilters() {
    @SuppressWarnings("unchecked")
    TableRowSorter<DefaultTableModel> sorter =
        (TableRowSorter<DefaultTableModel>) resultsTable.getRowSorter();
    if (sorter == null) return;

    String searchText = searchField.getText().toLowerCase();
    boolean vulnerableOnly = vulnerableOnlyCheckbox.isSelected();

    sorter.setRowFilter(
        new RowFilter<>() {
          @Override
          public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
            String name = entry.getStringValue(1).toLowerCase();
            boolean matchesSearch = name.contains(searchText);
            int vulns = (Integer) entry.getValue(4);
            return vulnerableOnly ? matchesSearch && vulns > 0 : matchesSearch;
          }
        });
  }

  public void runScan() {
    scanButton.setEnabled(false);
    setExportButtonsEnabled(false);
    statusLabel.setText("Scanning...");
    progressBar.setVisible(true);
    tableModel.setRowCount(0);
    scanResults.clear();
    VulnerabilityScannerService.getInstance(project).getScrapedVersions().clear(); // Clear cache on new scan
    scrapingInProgress.clear();

    VulnerabilityScannerService.getInstance(project)
        .scanDependencies()
        .thenAccept(
            results ->
                ApplicationManager.getApplication()
                    .invokeLater(
                        () -> {
                          scanResults.addAll(results);          VulnerabilityScannerService.getInstance(project).setLastResults(scanResults);
                          @SuppressWarnings("unchecked")
                          Vector<Vector<Object>> dataVector = (Vector) tableModel.getDataVector();
                          int firstRow = dataVector.size();
                          results.forEach(
                              result -> {
                                String highestSev = getHighestSeverity(result.vulnerabilities());
                                String fixedVer = getAggregateFixedVersion(result);
                                TableRowData rowData =
                                    new TableRowData(
                                        getSeverityIcon(highestSev),
                                        result.pkg().name(),
                                        result.pkg().version(),
                                        fixedVer,
                                        result.vulnerabilities().size());

                                Vector<Object> row = new Vector<>(5);
                                row.add(rowData.icon());
                                row.add(rowData.name());
                                row.add(rowData.version());
                                row.add(rowData.fixedIn());
                                row.add(rowData.vulnCount());
                                dataVector.add(row);

                                if (result.vulnerable() && UNKNOWN.equals(fixedVer)) {
                                  result.vulnerabilities().stream()
                                      .filter(
                                          v ->
                                              UNKNOWN.equals(
                                                  findFixedVersion(v, result.pkg().name(), result.pkg().version())))
                                      .forEach(v -> scrapeFixedVersion(v.id(), result));
                                }
                              });
                          if (!results.isEmpty()) {
                            tableModel.fireTableRowsInserted(firstRow, dataVector.size() - 1);
                            cardLayout.show(mainPanel, "RESULTS");
                          }
                          scanButton.setEnabled(true);
                          setExportButtonsEnabled(!results.isEmpty());
                          statusLabel.setText("Scan complete (" + results.size() + ")");
                          progressBar.setVisible(false);
                          applyFilters();
                        }))
        .exceptionally(
            ex -> {
              ApplicationManager.getApplication()
                  .invokeLater(
                      () -> {
                        scanButton.setEnabled(true);
                        setExportButtonsEnabled(false);
                        statusLabel.setText("Scan failed");
                        progressBar.setVisible(false);
                      });
              return null;
            });
  }

  private void exportReport(String format) {
    if (scanResults.isEmpty()) {
      statusLabel.setText("No scan data to export");
      return;
    }

    String extension = format.toLowerCase(Locale.ROOT);
    Path outputPath = chooseOutputPath(extension);
    if (outputPath == null) {
      return;
    }

    setExportButtonsEnabled(false);
    statusLabel.setText("Waiting for scraped versions...");
    scrapingLatch = new java.util.concurrent.CountDownLatch(scrapingInProgress.size());

    ApplicationManager.getApplication()
        .executeOnPooledThread(
            () -> {
              boolean timedOut;
              try {
                timedOut =
                    !scrapingLatch.await(
                        EXPORT_WAIT_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                timedOut = true;
              }

              String htmlReport =
                  VulnerabilityReportBuilder.buildProjectReport(
                      project.getName(), List.copyOf(scanResults), new HashMap<>(VulnerabilityScannerService.getInstance(project).getScrapedVersions()));

              try {
                if ("pdf".equals(extension)) {
                  ReportExportService.exportPdf(htmlReport, outputPath);
                } else if ("csv".equals(extension)) {
                  ReportExportService.exportCsv(List.copyOf(scanResults), outputPath);
                } else {
                  ReportExportService.exportHtml(htmlReport, outputPath);
                }

                final boolean partialExport = timedOut;
                ApplicationManager.getApplication()
                    .invokeLater(
                        () -> {
                          statusLabel.setText(
                              partialExport
                                  ? "Report exported with partial data: " + outputPath.getFileName()
                                  : "Report exported: " + outputPath.getFileName());
                          setExportButtonsEnabled(true);
                        });
              } catch (IOException ex) {
                ApplicationManager.getApplication()
                    .invokeLater(
                        () -> {
                          statusLabel.setText("Export failed");
                          setExportButtonsEnabled(true);
                        });
              }
            });
  }

  private Path chooseOutputPath(String extension) {
    String dateSuffix = LocalDate.now().toString();
    JFileChooser chooser =
        new JFileChooser(
            project.getBasePath() != null
                ? project.getBasePath()
                : System.getProperty("user.home"));
    chooser.setDialogTitle("Export vulnerability report");
    chooser.setFileFilter(
        new FileNameExtensionFilter(extension.toUpperCase(Locale.ROOT) + " files", extension));
    chooser.setSelectedFile(new File("sapo-vulnerability-report-" + dateSuffix + "." + extension));

    int selection = chooser.showSaveDialog(content);
    if (selection != JFileChooser.APPROVE_OPTION) {
      return null;
    }

    File selectedFile = chooser.getSelectedFile();
    String fileName = selectedFile.getName().toLowerCase(Locale.ROOT);
    if (!fileName.endsWith("." + extension)) {
      selectedFile =
          new File(selectedFile.getParentFile(), selectedFile.getName() + "." + extension);
    }
    return selectedFile.toPath();
  }

  private void setExportButtonsEnabled(boolean enabled) {
    exportHtmlButton.setEnabled(enabled);
    exportPdfButton.setEnabled(enabled);
    exportCsvButton.setEnabled(enabled);
  }

  private String getAggregateFixedVersion(VulnerabilityScannerService.ScanResult result) {
    if (!result.vulnerable()) return "";
    String versions =
        result.vulnerabilities().stream()
            .flatMap(
                vuln -> {
                  String f = findFixedVersion(vuln, result.pkg().name(), result.pkg().version());
                  f = UNKNOWN.equals(f) && VulnerabilityScannerService.getInstance(project).getScrapedVersions().containsKey(vuln.id())
                      ? VulnerabilityScannerService.getInstance(project).getScrapedVersions().get(vuln.id())
                      : f;
                  return UNKNOWN.equals(f) ? java.util.stream.Stream.<String>empty() : java.util.Arrays.stream(f.split(", "));
                })
            .distinct()
            .collect(java.util.stream.Collectors.joining(", "));
    return versions.isEmpty() ? UNKNOWN : versions;
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

  private String appendEscapedWithLineBreaks(String value) {
    if (value == null) {
      return "";
    }
    return HtmlEscaper.escape(value).replace("\n", "<br></br>");
  }

  private void appendHeader(StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    sb.append("<div class='header'>");
    sb.append("<h1>").append(HtmlEscaper.escape(result.pkg().name())).append("</h1>");
    sb.append("<div class='version'>Version: ")
        .append(HtmlEscaper.escape(result.pkg().version()))
        .append(DIV_CLOSE);
    sb.append(DIV_CLOSE);
  }

  private void appendVulnerableDetails(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    Set<String> fixedVersions =
        result.vulnerabilities().stream()
            .map(
                vuln -> {
                  String f = findFixedVersion(vuln, result.pkg().name(), result.pkg().version());
                  if (UNKNOWN.equals(f)) {
                    if (VulnerabilityScannerService.getInstance(project).getScrapedVersions().containsKey(vuln.id())) {
                      f = VulnerabilityScannerService.getInstance(project).getScrapedVersions().get(vuln.id());
                    } else {
                      scrapeFixedVersion(vuln.id(), result);
                    }
                  }
                  return f;
                })
            .filter(f -> !UNKNOWN.equals(f))
            .collect(java.util.stream.Collectors.toSet());

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
    if (chains == null || chains.isEmpty()) {
      return true;
    }
    return chains.stream()
        .peek(
            chain -> {
              if (chain.size() > 1) {
                roots.add(chain.getFirst());
              }
            })
        .anyMatch(chain -> chain.size() <= 1);
  }

  private void appendDirectRemediation(
      StringBuilder sb,
      VulnerabilityScannerService.ScanResult result,
      String fixedVerStr,
      boolean hasFix) {
    if (hasFix) {
      sb.append("<p>Upgrade <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append("</b> to version <b>")
          .append(HtmlEscaper.escape(fixedVerStr))
          .append("</b></p>");
    } else {
      sb.append("<p>No fixed version available for <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
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
      roots.forEach(
          root -> sb.append("<li><code>").append(HtmlEscaper.escape(root)).append("</code></li>"));
      sb.append("</ul>");
      sb.append("<p>to a version that uses <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append("</b> version <b>")
          .append(HtmlEscaper.escape(fixedVerStr))
          .append("</b>.</p>");
    } else {
      sb.append("<p>Transitive dependency <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append("</b> has no fixed version available.</p>");
      sb.append("<p>Affected roots:</p><ul>");
      roots.forEach(
          root -> sb.append("<li><code>").append(HtmlEscaper.escape(root)).append("</code></li>"));
      sb.append("</ul>");
    }
  }

  private void appendVulnerabilities(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    sb.append("<div class='section-title'>")
        .append(result.vulnerabilities().size())
        .append(" Vulnerabilities</div>");
    result
        .vulnerabilities()
        .forEach(
            vuln -> {
              String sev = getSeverity(vuln);
              String fixedV = findFixedVersion(vuln, result.pkg().name(), result.pkg().version());
              fixedV =
                  UNKNOWN.equals(fixedV) && VulnerabilityScannerService.getInstance(project).getScrapedVersions().containsKey(vuln.id())
                      ? VulnerabilityScannerService.getInstance(project).getScrapedVersions().get(vuln.id())
                      : fixedV;
              String score = getScore(vuln);

              sb.append("<div class='card'>");
              sb.append("<div class='card-header'>");
              sb.append("<span class='badge ")
                  .append(HtmlEscaper.escape(sev.toLowerCase(Locale.ROOT)))
                  .append("'>")
                  .append(HtmlEscaper.escape(sev))
                  .append("</span>");
              if (score != null) {
                sb.append("<span class='cvss-score'>CVSS ")
                    .append(HtmlEscaper.escape(score))
                    .append("</span>");
              }
              sb.append("<span class='vuln-id'><a href='https://osv.dev/vulnerability/")
                  .append(HtmlEscaper.escape(vuln.id()))
                  .append("'>")
                  .append(HtmlEscaper.escape(vuln.id()))
                  .append("</a></span>");
              sb.append(DIV_CLOSE);
              sb.append("<div class='vuln-summary'>")
                  .append(
                      vuln.summary() != null ? HtmlEscaper.escape(vuln.summary()) : "No summary")
                  .append(DIV_CLOSE);
              sb.append("<div class='fixed-box'>Fixed in: <span class='fixed-ver'>")
                  .append(HtmlEscaper.escape(fixedV))
                  .append("</span>");
              if (!UNKNOWN.equals(fixedV)) {
                sb.append(" <button class='copy-btn' onclick=\"copyToClipboard('")
                    .append(HtmlEscaper.escapeJsSingleQuoted(fixedV))
                    .append("')\">Copy</button>");
              }
              sb.append(DIV_CLOSE);
              sb.append("<div class='details'>")
                  .append(appendEscapedWithLineBreaks(vuln.details()))
                  .append(DIV_CLOSE);

              if (vuln.references() != null && !vuln.references().isEmpty()) {
                sb.append("<div class='references-section'>");
                sb.append("<div class='references-title'>References</div>");
                vuln.references()
                    .forEach(
                        ref -> {
                          String url = ref.url() == null ? "" : ref.url();
                          sb.append("<div class='reference-item'><a href='")
                              .append(HtmlEscaper.escape(url))
                              .append("'>")
                              .append(HtmlEscaper.escape(url))
                              .append("</a></div>");
                        });
                sb.append(DIV_CLOSE);
              }
              sb.append(DIV_CLOSE);
            });
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
            .append(HtmlEscaper.escape(project.getName()))
            .append(DIV_CLOSE);

        // Intermediate
        java.util.concurrent.atomic.AtomicInteger idx =
            new java.util.concurrent.atomic.AtomicInteger(0);
        chain.stream()
            .limit((long) chain.size() - 1)
            .forEach(
                item -> {
                  int i = idx.getAndIncrement();
                  sb.append("<div class='chain-item intermediate' style='padding-left: ")
                      .append((i + 1) * 20)
                      .append("px;'>");
                  sb.append("<span class='connector'>└─</span> <span class='icon'>📄</span> ")
                      .append(HtmlEscaper.escape(item));
                  sb.append(DIV_CLOSE);
                });

        // Target (Vulnerable)
        String target = chain.getLast();
        sb.append("<div class='chain-item target' style='padding-left: ")
            .append(chain.size() * 20)
            .append("px;'>");
        sb.append("<span class='connector'>└─</span> <span class='icon'>⚠️</span> <b>")
            .append(HtmlEscaper.escape(target))
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
              HttpURLConnection connection = null;
              try {
                URL url = new URI("https://osv.dev/vulnerability/" + vulnId).toURL();
                connection = (HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(SCRAPE_CONNECT_TIMEOUT_MS);
                connection.setReadTimeout(SCRAPE_READ_TIMEOUT_MS);
                connection.setRequestMethod("GET");

                String html;
                try (InputStream in = connection.getInputStream()) {
                  html = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                }

                // Regex to find "Fixed" followed by a version number in the HTML
                // Matches "Fixed" followed by tags/spaces and then a version number
                Matcher m = FIXED_VERSION_PATTERN.matcher(html);
                if (m.find()) {
                  String ver = m.group(1);
                  VulnerabilityScannerService.getInstance(project).getScrapedVersions().put(vulnId, ver);

                  ApplicationManager.getApplication()
                      .invokeLater(
                          () -> {
                            java.util.stream.IntStream.range(0, scanResults.size())
                                .filter(i -> scanResults.get(i).equals(result))
                                .findFirst()
                                .ifPresent(
                                    i ->
                                        tableModel.setValueAt(
                                            getAggregateFixedVersion(result), i, 3));

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
                if (connection != null) {
                  connection.disconnect();
                }
                scrapingInProgress.remove(vulnId);
                if (scrapingLatch != null) {
                  scrapingLatch.countDown();
                }
              }
            });
  }

  private String getScore(OsvVulnerability v) {
    if (v.severity() == null) return null;
    return v.severity().stream()
        .filter(s -> "CVSS_V3".equals(s.type()) || "CVSS_V2".equals(s.type()))
        .map(OsvVulnerability.Severity::score)
        .findFirst()
        .orElse(null);
  }

  private String generateHtml(String bodyContent) {
    boolean isDark = ColorUtil.isDark(UIUtil.getPanelBackground());
    HtmlTheme theme =
        new HtmlTheme(
            isDark ? "#1e1e1e" : "#ffffff",
            isDark ? "#d4d4d4" : "#333333",
            isDark ? "#252526" : "#ffffff",
            isDark ? "#454545" : "#e0e0e0");

    String headingColor = isDark ? "#ffffff" : "#000000";

    return "<html><head><style>"
        + "body { font-family: 'Inter', -apple-system, sans-serif; padding: 24px; background: "
        + theme.bgColor()
        + "; color: "
        + theme.textColor()
        + "; line-height: 1.6; }"
        + "h1 { font-size: 24px; font-weight: 700; margin: 0; color: "
        + headingColor
        + "; }"
        + ".version { color: #888; margin-top: 4px; margin-bottom: 24px; font-size: 14px; }"
        + ".section-title { font-weight: 700; margin-top: 24px; margin-bottom: 12px; font-size: 16px; border-bottom: 1px solid "
        + theme.borderColor()
        + "; padding-bottom: 8px; }"
        + ".safe-banner { background: rgba(67, 160, 71, 0.1); color: #43a047; padding: 16px; border-radius: 8px; font-weight: 600; margin: 24px 0; border: 1px solid #43a047; }"
        + ".path-header { font-weight: 600; margin-top: 16px; margin-bottom: 8px; color: #2196f3; font-size: 14px; }"
        + ".snyk-chain { font-family: 'JetBrains Mono', monospace; background: "
        + (isDark ? "#2d2d2d" : "#f5f5f5")
        + "; padding: 12px; border-radius: 6px; margin: 8px 0; font-size: 13px; }"
        + ".chain-item { padding: 4px 0; display: flex; align-items: center; }"
        + ".connector { color: #888; margin-right: 8px; }"
        + ".icon { margin-right: 6px; }"
        + ".target { color: #e53935; font-weight: 700; }"
        + ".remediation-box { background: "
        + (isDark ? "#1a2a3a" : "#e3f2fd")
        + "; border: 1px solid #2196f3; border-radius: 8px; padding: 16px; margin: 16px 0; }"
        + ".remediation-title { font-weight: 800; color: #2196f3; text-transform: uppercase; font-size: 12px; margin-bottom: 8px; letter-spacing: 0.5px; }"
        + ".card { background: "
        + theme.cardBg()
        + "; border: 1px solid "
        + theme.borderColor()
        + "; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }"
        + ".card-header { display: flex; align-items: center; margin-bottom: 12px; gap: 10px; }"
        + ".badge { padding: 4px 10px; border-radius: 20px; color: white; font-size: 11px; font-weight: 700; text-transform: uppercase; }"
        + ".cvss-score { font-size: 12px; font-weight: 600; color: #888; background: "
        + (isDark ? "#333" : "#eee")
        + "; padding: 2px 8px; border-radius: 4px; }"
        + ".critical { background: #d32f2f; } .high { background: #f57c00; } .medium { background: #fbc02d; color: #333; } .low { background: #43a047; }"
        + ".vuln-id { font-weight: 600; font-size: 14px; }"
        + ".vuln-summary { font-size: 16px; font-weight: 600; margin-bottom: 12px; color: "
        + (isDark ? "#eee" : "#222")
        + "; }"
        + ".fixed-box { background: rgba(67, 160, 71, 0.1); color: #2e7d32; padding: 8px 12px; border-radius: 6px; font-weight: 600; display: inline-flex; align-items: center; gap: 8px; margin: 12px 0; border: 1px solid rgba(67, 160, 71, 0.2); }"
        + ".copy-btn { cursor: pointer; background: #2196f3; color: white; border: none; padding: 2px 8px; border-radius: 4px; font-size: 10px; transition: background 0.2s; }"
        + ".copy-btn:hover { background: #1976d2; }"
        + ".details { font-size: 13px; color: #888; margin-top: 12px; max-height: 150px; overflow-y: auto; background: "
        + (isDark ? "#1e1e1e" : "#fcfcfc")
        + "; padding: 10px; border-radius: 4px; }"
        + ".references-section { margin-top: 20px; border-top: 1px solid "
        + theme.borderColor()
        + "; padding-top: 16px; }"
        + ".references-title { font-weight: 800; color: #888; text-transform: uppercase; font-size: 11px; margin-bottom: 10px; }"
        + ".reference-item { font-size: 12px; margin-bottom: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }"
        + "a { color: #2196f3; text-decoration: none; font-weight: 500; } a:hover { text-decoration: underline; }"
        + "code { font-family: 'JetBrains Mono', monospace; background: rgba(0,0,0,0.05); padding: 2px 4px; border-radius: 3px; }"
        + "</style>"
        + "<script>"
        + "function copyToClipboard(text) {"
        + "  const el = document.createElement('textarea');"
        + "  el.value = text;"
        + "  document.body.appendChild(el);"
        + "  el.select();"
        + "  document.execCommand('copy');"
        + "  document.body.removeChild(el);"
        + "  const btn = event.target;"
        + "  const originalText = btn.innerText;"
        + "  btn.innerText = 'Copied!';"
        + "  setTimeout(() => btn.innerText = originalText, 2000);"
        + "}"
        + "</script>"
        + "</head><body>"
        + bodyContent
        + "</body></html>";
  }

  private String getHighestSeverity(List<OsvVulnerability> vulns) {
    return severityAnalyzer.getHighestSeverity(vulns);
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
    return severityAnalyzer.getSeverity(v);
  }

  private String findFixedVersion(OsvVulnerability v, String pkgName, String currentVersion) {
    if (v.affected() == null) return UNKNOWN;
    List<String> fixedVersions = v.affected().stream()
        .filter(a -> a.pkg() == null || isMatchingPackage(pkgName, a.pkg().name()))
        .filter(a -> a.ranges() != null)
        .flatMap(a -> a.ranges().stream())
        .filter(r -> r.events() != null)
        .flatMap(r -> r.events().stream())
        .map(OsvVulnerability.Event::fixed)
        .filter(Objects::nonNull)
        .distinct()
        .toList();

    if (fixedVersions.isEmpty()) return UNKNOWN;
    if (currentVersion == null || currentVersion.isBlank()) {
        return String.join(", ", fixedVersions);
    }

    String best = VersionUtil.findBestFixedVersion(fixedVersions, currentVersion);
    if (best != null) {
        return best;
    }

    return String.join(", ", fixedVersions);
  }

  private boolean isMatchingPackage(String scannedPkg, String vulnPkg) {
    if (scannedPkg == null || vulnPkg == null) return false;
    if (scannedPkg.equals(vulnPkg)) return true;

    // Check if one is a suffix of the other (e.g. "jackson-core" vs "com.fasterxml.jackson.core:jackson-core")
    if (vulnPkg.endsWith(":" + scannedPkg)) return true;
    if (scannedPkg.endsWith(":" + vulnPkg)) return true;

    // Further check for just the artifact ID just in case
    String scannedArtifact = scannedPkg.contains(":") ? scannedPkg.substring(scannedPkg.indexOf(':') + 1) : scannedPkg;
    String vulnArtifact = vulnPkg.contains(":") ? vulnPkg.substring(vulnPkg.indexOf(':') + 1) : vulnPkg;

    return scannedArtifact.equals(vulnArtifact);
  }

  public JComponent getContent() {
    return content;
  }

  private record HtmlTheme(String bgColor, String textColor, String cardBg, String borderColor) {}

  private record ScrapingTask(String vulnId, VulnerabilityScannerService.ScanResult result) {}

  private record TableRowData(
      Icon icon, String name, String version, String fixedIn, int vulnCount) {}
}
