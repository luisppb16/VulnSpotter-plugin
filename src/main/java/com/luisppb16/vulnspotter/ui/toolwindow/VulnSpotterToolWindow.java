/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.ui.toolwindow;

import com.intellij.icons.AllIcons;
import com.intellij.ide.BrowserUtil;
import com.intellij.ide.ui.LafManagerListener;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.fileChooser.FileChooserFactory;
import com.intellij.openapi.fileChooser.FileSaverDescriptor;
import com.intellij.openapi.ide.CopyPasteManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Splitter;
import com.intellij.openapi.ui.popup.JBPopupFactory;
import com.intellij.openapi.ui.popup.ListPopup;
import com.intellij.openapi.ui.popup.ListPopupStep;
import com.intellij.openapi.ui.popup.PopupStep;
import com.intellij.openapi.ui.popup.util.BaseListPopupStep;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.vfs.VirtualFileWrapper;
import com.intellij.ui.ColorUtil;
import com.intellij.ui.DocumentAdapter;
import com.intellij.ui.JBColor;
import com.intellij.ui.SearchTextField;
import com.intellij.ui.awt.RelativePoint;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.table.JBTable;
import com.intellij.util.ExceptionUtil;
import com.intellij.util.IconUtil;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.model.Ecosystem;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.domain.service.FixedVersionResolver;
import com.luisppb16.vulnspotter.domain.service.SeverityAnalyzer;
import com.luisppb16.vulnspotter.infrastructure.osv.ProjectConstants;
import com.luisppb16.vulnspotter.infrastructure.parser.IgnoreFileStore;
import com.luisppb16.vulnspotter.infrastructure.report.ReportExportService;
import com.luisppb16.vulnspotter.infrastructure.report.VulnerabilityCardComposer;
import com.luisppb16.vulnspotter.infrastructure.report.VulnerabilityReportBuilder;
import com.luisppb16.vulnspotter.ui.notification.VulnSpotterNotifications;
import com.luisppb16.vulnspotter.util.HtmlEscaper;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.io.Serial;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

/**
 * Tool window UI for VulnSpotter: results table with severity ranking plus an HTML details panel
 * (JCEF when available, Swing fallback otherwise).
 */
public final class VulnSpotterToolWindow implements Disposable {

  private static final String UNKNOWN = FixedVersionResolver.UNKNOWN;
  private static final String DIV_CLOSE = "</div>";
  private static final String EMPTY_DETAILS_HTML =
      "<h1>VulnSpotter</h1><p>Select a dependency to see details.</p>";

  private static final String COPY_TO_CLIPBOARD_JS =
      """
      function copyToClipboard(text) {
        const el = document.createElement('textarea');
        el.value = text;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
        const btn = event.target;
        const originalText = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => btn.innerText = originalText, 2000);
      }
      """;
  private static final JBColor COLOR_CRITICAL = new JBColor(0xB71C1C, 0xEF5350);
  private static final JBColor COLOR_HIGH = new JBColor(0xE65100, 0xFFA726);
  private static final JBColor COLOR_MEDIUM = new JBColor(0xF57F17, 0xFFEE58);
  private static final JBColor COLOR_LOW = new JBColor(0x33691E, 0x9CCC65);
  private static final long SCAN_TIMEOUT_SECONDS = 300;

  private final JPanel content;
  private final CardLayout cardLayout = new CardLayout();
  private final JPanel mainPanel;
  private final JBTable resultsTable;
  private final TableRowSorter<DefaultTableModel> resultsSorter;
  private final DefaultTableModel tableModel;
  private final DetailsPanel detailsPanel;
  private final Project project;
  private final JButton scanButton;
  private final JButton cancelButton;
  private final JButton exportButton;
  private final JLabel statusLabel;
  private final SearchTextField searchField;
  private final JBCheckBox vulnerableOnlyCheckbox;
  private final JProgressBar progressBar;
  private final List<VulnerabilityScannerService.ScanResult> scanResults = new ArrayList<>();

  /**
   * Pre-lowercased "package name + ids + aliases" text per row, aligned with {@link #scanResults},
   * so the live filter matches by a single {@code contains} per row instead of re-lowercasing every
   * field on every keystroke.
   */
  private final List<String> searchBlobs = new ArrayList<>();

  /** Precomputed severity icons; emptied on theme change so colors re-resolve. */
  private final Map<String, Icon> severityIcons = new HashMap<>();

  /** Prebuilt light/dark document shells; only the body varies between renders. */
  private final Map<Boolean, String> htmlShells = new HashMap<>();

  private volatile CompletableFuture<List<VulnerabilityScannerService.ScanResult>> activeScan;

  public VulnSpotterToolWindow(Project project) {
    this.project = project;
    this.content = new JPanel(new BorderLayout());

    DetailsPanelFactory factory =
        ApplicationManager.getApplication().getService(DetailsPanelFactory.class);
    DetailsPanel panel = factory.create();
    this.detailsPanel = panel != null ? panel : new SwingDetailsPanel();
    Disposer.register(this, detailsPanel);

    JPanel toolbar = new JPanel(new BorderLayout());
    toolbar.setBorder(JBUI.Borders.empty(4, 8));

    JPanel leftActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
    scanButton = new JButton("Scan Dependencies", AllIcons.Actions.Execute);
    scanButton.addActionListener(e -> runScan());
    leftActions.add(scanButton);

    cancelButton = new JButton("Cancel", AllIcons.Actions.Suspend);
    cancelButton.setVisible(false);
    cancelButton.addActionListener(e -> cancelScan());
    leftActions.add(cancelButton);

    vulnerableOnlyCheckbox = new JBCheckBox("Vulnerable only", true);
    vulnerableOnlyCheckbox.addActionListener(e -> applyFilters());
    leftActions.add(vulnerableOnlyCheckbox);

    exportButton = new JButton("Export…", AllIcons.ToolbarDecorator.Export);
    exportButton.setEnabled(false);
    exportButton.addActionListener(e -> showExportMenu());
    leftActions.add(exportButton);

    statusLabel = new JLabel("Ready");
    leftActions.add(statusLabel);

    progressBar = new JProgressBar();
    progressBar.setIndeterminate(true);
    progressBar.setVisible(false);
    progressBar.setPreferredSize(JBUI.size(100, 16));
    leftActions.add(progressBar);

    searchField = new SearchTextField();
    searchField.addDocumentListener(
        new DocumentAdapter() {
          @Override
          protected void textChanged(DocumentEvent e) {
            applyFilters();
          }
        });
    searchField.setPreferredSize(JBUI.size(250, 30));
    searchField.setMinimumSize(JBUI.size(250, 30));
    searchField.setMaximumSize(JBUI.size(250, 30));

    toolbar.add(leftActions, BorderLayout.WEST);
    content.add(toolbar, BorderLayout.NORTH);

    Splitter splitter = new Splitter(false, 0.35f);

    tableModel =
        new DefaultTableModel(
            new String[] {"Severity", "Dependency", "Version", "Fixed In", "Vulns"}, 0) {
          @Override
          public boolean isCellEditable(int row, int column) {
            return false;
          }

          @Override
          public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 4) return Integer.class;
            return String.class;
          }
        };
    resultsTable = new JBTable(tableModel);
    resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

    resultsSorter = new TableRowSorter<>(tableModel);
    resultsSorter.setComparator(
        0, Comparator.comparingInt(sev -> SeverityAnalyzer.severityToLevel((String) sev)));
    resultsTable.setRowSorter(resultsSorter);
    // Most severe first, then alphabetically by dependency
    resultsSorter.setSortKeys(
        List.of(
            new RowSorter.SortKey(0, SortOrder.DESCENDING),
            new RowSorter.SortKey(1, SortOrder.ASCENDING)));

    TableColumn severityColumn = resultsTable.getColumnModel().getColumn(0);
    severityColumn.setPreferredWidth(90);
    severityColumn.setMaxWidth(110);
    severityColumn.setMinWidth(80);
    severityColumn.setCellRenderer(new SeverityCellRenderer());

    TableColumn vulnsColumn = resultsTable.getColumnModel().getColumn(4);
    vulnsColumn.setPreferredWidth(50);
    vulnsColumn.setMaxWidth(70);
    vulnsColumn.setMinWidth(40);

    resultsTable.getEmptyText().setText("No results");

    resultsTable
        .getSelectionModel()
        .addListSelectionListener(
            e -> {
              if (!e.getValueIsAdjusting()) {
                selectedResult().ifPresent(this::showDetails);
              }
            });

    resultsTable.setComponentPopupMenu(createTablePopupMenu());

    JPanel leftPanel = new JPanel(new BorderLayout());
    JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 5));
    searchPanel.setBorder(JBUI.Borders.empty(0, 5, 5, 0));
    searchPanel.add(searchField);
    leftPanel.add(searchPanel, BorderLayout.NORTH);
    leftPanel.add(new JBScrollPane(resultsTable), BorderLayout.CENTER);

    splitter.setFirstComponent(leftPanel);
    splitter.setSecondComponent(detailsPanel.getComponent());

    mainPanel = new JPanel(cardLayout);
    mainPanel.add(createEmptyStatePanel(), "EMPTY");
    mainPanel.add(splitter, "RESULTS");

    content.add(mainPanel, BorderLayout.CENTER);
    cardLayout.show(mainPanel, "EMPTY");

    loadDetailsHtml(generateHtml(EMPTY_DETAILS_HTML));

    // Re-render the details panel when the IDE theme changes
    ApplicationManager.getApplication()
        .getMessageBus()
        .connect(this)
        .subscribe(
            LafManagerListener.TOPIC,
            (LafManagerListener)
                source -> {
                  severityIcons.clear();
                  htmlShells.clear();
                  Optional<VulnerabilityScannerService.ScanResult> selected = selectedResult();
                  selected.ifPresentOrElse(
                      this::showDetails, () -> loadDetailsHtml(generateHtml(EMPTY_DETAILS_HTML)));
                });
  }

  private static String classificationLabel(boolean isDirect, Set<String> roots) {
    if (isDirect && roots.isEmpty()) {
      return "Direct dependency";
    }
    if (!isDirect) {
      return "Transitive dependency";
    }
    return "Direct and transitive dependency";
  }

  /** Pre-lowercased "name + vulnerability ids + aliases" text searched by the live filter. */
  private static String buildSearchBlob(VulnerabilityScannerService.ScanResult result) {
    StringBuilder blob = new StringBuilder(result.pkg().name().toLowerCase(Locale.ROOT));
    for (OsvVulnerability vuln : result.vulnerabilities()) {
      appendSearchTerm(blob, vuln.id());
      vuln.aliases().forEach(alias -> appendSearchTerm(blob, alias));
    }
    return blob.toString();
  }

  private static void appendSearchTerm(StringBuilder blob, String term) {
    if (term != null && !term.isBlank()) {
      blob.append('\n').append(term.toLowerCase(Locale.ROOT));
    }
  }

  private static String buildHtmlShell(boolean isDark) {
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
        + ".dep-classification { font-size: 12px; font-weight: 600; color: "
        + (isDark ? "#9db8d8" : "#1565c0")
        + "; margin-bottom: 10px; }"
        + ".ecosystem-tag { display: inline-block; background: "
        + (isDark ? "#333" : "#eee")
        + "; color: "
        + (isDark ? "#ccc" : "#555")
        + "; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 4px; }"
        + ".affected-range { font-size: 12px; color: #888; margin: 8px 0; font-family: 'JetBrains Mono', monospace; }"
        + ".card { background: "
        + theme.cardBg()
        + "; border: 1px solid "
        + theme.borderColor()
        + "; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }"
        + ".card-header { display: flex; align-items: center; margin-bottom: 12px; gap: 10px; flex-wrap: wrap; }"
        + ".badge { padding: 4px 10px; border-radius: 20px; color: white; font-size: 11px; font-weight: 700; text-transform: uppercase; }"
        + ".cvss-score { font-size: 12px; font-weight: 600; color: #888; background: "
        + (isDark ? "#333" : "#eee")
        + "; padding: 2px 8px; border-radius: 4px; }"
        + VulnerabilityCardComposer.badgeCssRules()
        + ".vuln-id { font-weight: 600; font-size: 14px; }"
        + ".cve-alias { font-size: 12px; margin-left: 4px; }"
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
        + COPY_TO_CLIPBOARD_JS
        + "</script>"
        + "</head><body>";
  }

  private static Icon resolveSeverityIcon(String s) {
    return switch (s) {
      case SeverityAnalyzer.CRITICAL -> IconUtil.colorize(AllIcons.General.Error, COLOR_CRITICAL);
      case SeverityAnalyzer.HIGH -> IconUtil.colorize(AllIcons.General.Warning, COLOR_HIGH);
      case SeverityAnalyzer.MEDIUM -> IconUtil.colorize(AllIcons.General.Note, COLOR_MEDIUM);
      case SeverityAnalyzer.LOW -> IconUtil.colorize(AllIcons.General.Information, COLOR_LOW);
      case SeverityAnalyzer.UNKNOWN -> AllIcons.General.QuestionDialog;
      default -> IconUtil.colorize(AllIcons.General.InspectionsOK, COLOR_LOW);
    };
  }

  @Override
  public void dispose() {
    cancelScan();
  }

  /** Cancels the in-flight scan, if any. */
  private void cancelScan() {
    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> scan = activeScan;
    if (scan != null) {
      scan.cancel(true);
    }
  }

  private void loadDetailsHtml(String html) {
    detailsPanel.loadHtml(html);
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

  private JPopupMenu createTablePopupMenu() {
    JPopupMenu menu = new JPopupMenu();

    JMenuItem openOsv = new JMenuItem("Open in OSV.dev", AllIcons.Ide.External_link_arrow);
    openOsv.addActionListener(
        e ->
            withSelectedResult(
                result ->
                    result.vulnerabilities().stream()
                        .findFirst()
                        .ifPresent(
                            v -> BrowserUtil.browse(ProjectConstants.OSV_WEB_VULN_URL + v.id()))));
    menu.add(openOsv);

    // Submenu to open every vulnerability advisory of the selected dependency at once.
    JMenu openAll = new JMenu("Open all vulnerabilities");
    openAll.setIcon(AllIcons.Ide.External_link_arrow);
    openAll.addMenuListener(
        new MenuListener() {
          @Override
          public void menuSelected(MenuEvent e) {
            openAll.removeAll();
            selectedResult()
                .filter(result -> !result.vulnerabilities().isEmpty())
                .ifPresentOrElse(
                    result -> {
                      for (OsvVulnerability vuln : result.vulnerabilities()) {
                        JMenuItem item = new JMenuItem(vuln.id());
                        item.addActionListener(
                            ev ->
                                BrowserUtil.browse(ProjectConstants.OSV_WEB_VULN_URL + vuln.id()));
                        openAll.add(item);
                      }
                    },
                    () -> openAll.add(new JMenuItem("No vulnerabilities")));
          }

          @Override
          public void menuDeselected(MenuEvent e) {}

          @Override
          public void menuCanceled(MenuEvent e) {}
        });
    menu.add(openAll);

    menu.addSeparator();

    JMenuItem copyCoordinate = new JMenuItem("Copy Dependency Coordinate");
    copyCoordinate.addActionListener(
        e ->
            withSelectedResult(
                result ->
                    CopyPasteManager.getInstance()
                        .setContents(
                            new StringSelection(
                                result.pkg().name() + ":" + result.pkg().version()))));
    menu.add(copyCoordinate);

    JMenuItem copyFix = new JMenuItem("Copy Recommended Fix Version");
    copyFix.addActionListener(
        e ->
            withSelectedResult(
                result ->
                    FixedVersionResolver.recommendUpgrade(
                            result.vulnerabilities(), result.pkg().name(), result.pkg().version())
                        .ifPresent(
                            fix ->
                                CopyPasteManager.getInstance()
                                    .setContents(new StringSelection(fix)))));
    menu.add(copyFix);

    JMenuItem copySnippet = new JMenuItem("Copy Upgrade Snippet");
    copySnippet.setToolTipText("Copy a manifest snippet that pins the recommended fixed version.");
    copySnippet.addActionListener(
        e ->
            withSelectedResult(
                result ->
                    FixedVersionResolver.recommendUpgrade(
                            result.vulnerabilities(), result.pkg().name(), result.pkg().version())
                        .ifPresent(
                            fix ->
                                CopyPasteManager.getInstance()
                                    .setContents(
                                        new StringSelection(
                                            Ecosystem.upgradeSnippet(
                                                result.pkg().ecosystem(),
                                                result.pkg().name(),
                                                fix))))));
    menu.add(copySnippet);

    menu.addSeparator();

    JMenuItem ignore = new JMenuItem("Ignore this Dependency", AllIcons.Actions.Cancel);
    ignore.addActionListener(e -> withSelectedResult(this::ignoreDependency));
    menu.add(ignore);

    return menu;
  }

  private void ignoreDependency(VulnerabilityScannerService.ScanResult result) {
    String entry = result.pkg().name();
    ApplicationManager.getApplication()
        .executeOnPooledThread(
            () -> {
              try {
                IgnoreFileStore.appendEntry(project, entry);
                ApplicationManager.getApplication()
                    .invokeLater(
                        () ->
                            VulnSpotterNotifications.notifyInfo(
                                project,
                                VulnSpotterNotifications.TITLE,
                                "Added \"" + entry + "\" to .vulnspotterignore. Re-scan to apply."),
                        project.getDisposed());
              } catch (IOException ex) {
                ApplicationManager.getApplication()
                    .invokeLater(
                        () ->
                            VulnSpotterNotifications.notifyError(
                                project,
                                VulnSpotterNotifications.TITLE,
                                "Could not update .vulnspotterignore: " + ex.getMessage()),
                        project.getDisposed());
              }
            });
  }

  /** The scan result backing the currently selected table row, or empty when none is selected. */
  private Optional<VulnerabilityScannerService.ScanResult> selectedResult() {
    int row = resultsTable.getSelectedRow();
    if (row < 0) {
      return Optional.empty();
    }
    int modelRow = resultsTable.convertRowIndexToModel(row);
    return modelRow < scanResults.size()
        ? Optional.of(scanResults.get(modelRow))
        : Optional.empty();
  }

  private void withSelectedResult(Consumer<VulnerabilityScannerService.ScanResult> consumer) {
    selectedResult().ifPresent(consumer);
  }

  private void applyFilters() {
    String searchText = searchField.getText().toLowerCase(Locale.ROOT);
    boolean vulnerableOnly = vulnerableOnlyCheckbox.isSelected();
    boolean hasSearch = !searchText.isEmpty();

    resultsSorter.setRowFilter(
        new RowFilter<>() {
          @Override
          public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
            int vulns = (Integer) entry.getValue(4);
            if (vulnerableOnly && vulns <= 0) {
              return false;
            }
            if (!hasSearch) {
              return true;
            }
            // Also match CVE aliases and vulnerability ids so users can search "CVE-2024-1234";
            // the prebuilt blob covers name and every id/alias of the row.
            int modelRow = entry.getIdentifier();
            String blob =
                modelRow >= 0 && modelRow < searchBlobs.size() ? searchBlobs.get(modelRow) : "";
            return blob.contains(searchText);
          }
        });

    updateEmptyText();
  }

  private void updateEmptyText() {
    if (scanResults.isEmpty()) {
      resultsTable.getEmptyText().setText("No results");
      return;
    }
    // One short-circuited pass: applyFilters runs per keystroke, and only the "any vulnerable"
    // question is needed (never the counts a full ScanSummary roll-up computes).
    if (vulnerableOnlyCheckbox.isSelected()
        && scanResults.stream().noneMatch(VulnerabilityScannerService.ScanResult::vulnerable)) {
      resultsTable
          .getEmptyText()
          .setText(
              "No vulnerable dependencies ("
                  + scanResults.size()
                  + " scanned) — uncheck 'Vulnerable only' to see all");
    } else {
      resultsTable.getEmptyText().setText("No dependencies match the current filters");
    }
  }

  public void runScan() {
    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> future =
        VulnerabilityScannerService.getInstance(project)
            .scanDependencies(true)
            .orTimeout(SCAN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    activeScan = future;
    ScanUiPhase.SCANNING.apply(this, "Scanning...", false);

    future
        .thenAccept(
            results ->
                ApplicationManager.getApplication()
                    .invokeLater(
                        () -> {
                          if (activeScan != future) {
                            // A newer scan superseded this one: never paint its stale results,
                            // overwrite the annotator's data or release the new scan's guard.
                            return;
                          }
                          onScanFinished(results);
                        },
                        project.getDisposed()))
        .exceptionally(
            ex -> {
              ApplicationManager.getApplication()
                  .invokeLater(
                      () -> {
                        if (activeScan != future) {
                          // On failure too: only the newest scan may reset the UI state.
                          return;
                        }
                        onScanFailed(ex);
                      },
                      project.getDisposed());
              return null;
            });
  }

  private void onScanFinished(List<VulnerabilityScannerService.ScanResult> results) {
    activeScan = null;
    scanResults.addAll(results);
    results.forEach(result -> searchBlobs.add(buildSearchBlob(result)));
    // Publication (annotator refresh) is owned by the service; this panel only paints.
    VulnerabilityScannerService.ScanSummary summary =
        VulnerabilityScannerService.ScanSummary.of(results);

    // Bulk insert: one table event (and one sorter pass) per scan, not per row.
    List<Object[]> rows =
        results.stream()
            .map(
                result -> {
                  String highestSev =
                      result.vulnerable()
                          ? SeverityAnalyzer.getHighestSeverity(result.vulnerabilities())
                          : SeverityAnalyzer.SAFE;
                  String fixedVer =
                      result.vulnerable()
                          ? FixedVersionResolver.recommendUpgrade(
                                  result.vulnerabilities(),
                                  result.pkg().name(),
                                  result.pkg().version())
                              .orElse(UNKNOWN)
                          : "";
                  return new Object[] {
                    highestSev,
                    result.pkg().name(),
                    result.pkg().version(),
                    fixedVer,
                    result.vulnerabilities().size()
                  };
                })
            .toList();
    insertRows(rows);

    if (!results.isEmpty()) {
      cardLayout.show(mainPanel, "RESULTS");
      ScanUiPhase.RESULTS.apply(
          this,
          summary.vulnerable() + " vulnerable of " + summary.scanned() + " dependencies scanned",
          true);
      if (summary.vulnerable() > 0) {
        VulnSpotterNotifications.notifyWarning(
            project,
            "VulnSpotter found vulnerabilities",
            summary.vulnerable()
                + " vulnerable dependenc"
                + (summary.vulnerable() == 1 ? "y" : "ies")
                + " of "
                + summary.scanned()
                + " scanned. Open the VulnSpotter tool window for remediation advice.");
      }
    } else {
      ScanUiPhase.NO_DEPS.apply(
          this, "No dependencies found — make sure the project is synced", false);
    }

    applyFilters();
  }

  /** Appends the rows with a single table event. */
  @SuppressWarnings({"unchecked", "rawtypes"})
  private void insertRows(List<Object[]> rows) {
    Vector<Vector> dataVector = tableModel.getDataVector();
    int firstRow = dataVector.size();
    for (Object[] cells : rows) {
      Vector<Object> row = new Vector<>(Arrays.asList(cells));
      dataVector.add(row);
    }
    if (!rows.isEmpty()) {
      tableModel.fireTableRowsInserted(firstRow, dataVector.size() - 1);
    }
  }

  private void onScanFailed(Throwable ex) {
    activeScan = null;

    Throwable cause = ExceptionUtil.unwrapException(ex, CompletionException.class);
    if (cause instanceof CancellationException _) {
      ScanUiPhase.CANCELLED.apply(this, "Scan cancelled", false);
      return;
    }
    String message =
        switch (cause) {
          case TimeoutException _ ->
              "The scan timed out after "
                  + SCAN_TIMEOUT_SECONDS
                  + "s. Try again or narrow the project.";
          default -> ExceptionUtil.getNonEmptyMessage(cause, cause.getClass().getSimpleName());
        };
    ScanUiPhase.FAILED.apply(this, "Scan failed: " + message, false);
    VulnSpotterNotifications.notifyError(
        project,
        "VulnSpotter scan failed",
        "The vulnerability scan could not be completed: " + message);
  }

  private void showExportMenu() {
    List<String> items =
        List.of(
            "Export HTML",
            "Export PDF",
            "Export CSV",
            "Export SARIF",
            "Export JSON",
            "Export Markdown");
    // A JBPopup list renders each row with the IDE's native selection styling, so the option under
    // the cursor is clearly highlighted in both light and dark themes (and keyboard-navigable),
    // unlike a plain JPopupMenu whose hover cue depends on the host look-and-feel.
    ListPopupStep<String> step =
        new BaseListPopupStep<String>("Export report", items) {
          @Override
          public PopupStep<?> onChosen(String selected, boolean finalChoice) {
            exportReport(selected.substring("Export ".length()).toLowerCase(Locale.ROOT));
            return PopupStep.FINAL_CHOICE;
          }
        };
    ListPopup popup = JBPopupFactory.getInstance().createListPopup(step);
    popup.show(new RelativePoint(exportButton, new Point(0, exportButton.getHeight())));
  }

  private void exportReport(String extension) {
    if (scanResults.isEmpty()) {
      statusLabel.setText("No scan data to export");
      return;
    }

    Path outputPath = chooseOutputPath(extension);
    if (outputPath == null) {
      return;
    }

    // Snapshot on the EDT so a concurrent re-scan can't mutate the list mid-export
    List<VulnerabilityScannerService.ScanResult> snapshot = List.copyOf(scanResults);

    exportButton.setEnabled(false);
    statusLabel.setText("Exporting...");

    ApplicationManager.getApplication()
        .executeOnPooledThread(
            () -> {
              try {
                switch (extension) {
                  case "pdf" ->
                      ReportExportService.exportPdf(
                          VulnerabilityReportBuilder.buildProjectReport(
                              project.getName(), snapshot),
                          outputPath);
                  case "csv" -> ReportExportService.exportCsv(snapshot, outputPath);
                  case "sarif" -> ReportExportService.exportSarif(snapshot, outputPath);
                  case "json" ->
                      ReportExportService.exportJsonReport(project.getName(), snapshot, outputPath);
                  case "markdown" ->
                      ReportExportService.exportMarkdown(project.getName(), snapshot, outputPath);
                  default ->
                      ReportExportService.exportHtml(
                          VulnerabilityReportBuilder.buildProjectReport(
                              project.getName(), snapshot),
                          outputPath);
                }

                ApplicationManager.getApplication()
                    .invokeLater(
                        () -> statusLabel.setText("Report exported: " + outputPath.getFileName()),
                        project.getDisposed());
              } catch (Exception ex) {
                ApplicationManager.getApplication()
                    .invokeLater(
                        () -> {
                          String message =
                              ExceptionUtil.getNonEmptyMessage(ex, ex.getClass().getSimpleName());
                          statusLabel.setText("Export failed: " + message);
                          VulnSpotterNotifications.notifyError(
                              project, "VulnSpotter export failed", message);
                        },
                        project.getDisposed());
              } finally {
                ApplicationManager.getApplication()
                    .invokeLater(() -> exportButton.setEnabled(true), project.getDisposed());
              }
            });
  }

  private Path chooseOutputPath(String extension) {
    String fileExt = "markdown".equals(extension) ? "md" : extension;
    FileSaverDescriptor descriptor =
        new FileSaverDescriptor(
            "Export Vulnerability Report",
            "Choose where to save the " + extension.toUpperCase(Locale.ROOT) + " report",
            fileExt);
    String defaultName = "vulnspotter-report-" + LocalDate.now() + "." + fileExt;
    VirtualFileWrapper wrapper =
        FileChooserFactory.getInstance()
            .createSaveFileDialog(descriptor, project)
            .save(defaultName);
    return wrapper != null ? wrapper.getFile().toPath() : null;
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

    loadDetailsHtml(generateHtml(sb.toString()));
  }

  private void appendHeader(StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    sb.append("<div class='header'>");
    sb.append("<h1>").append(HtmlEscaper.escape(result.pkg().name())).append("</h1>");
    String ecosystem = result.pkg().ecosystem();
    sb.append("<div class='version'>");
    if (ecosystem != null && !ecosystem.isBlank()) {
      sb.append("<span class='ecosystem-tag'>")
          .append(HtmlEscaper.escape(ecosystem))
          .append("</span> ");
    }
    sb.append("Version: ").append(HtmlEscaper.escape(result.pkg().version()));
    sb.append(DIV_CLOSE);
    sb.append(DIV_CLOSE);
  }

  private void appendVulnerableDetails(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    String recommended =
        FixedVersionResolver.recommendUpgrade(
                result.vulnerabilities(), result.pkg().name(), result.pkg().version())
            .orElse(null);

    appendRemediation(sb, result, recommended);
    appendVulnerabilities(sb, result);
  }

  private void appendRemediation(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result, String recommended) {
    sb.append("<div class='remediation-box'>");
    sb.append("<div class='remediation-title'>Remediation</div>");

    Set<List<String>> chains = result.pkg().dependencyChains();
    Set<String> roots = new HashSet<>();
    boolean isDirect = isDirectDependency(chains, roots);
    String fixedVerStr = recommended != null ? recommended : UNKNOWN;

    sb.append("<div class='dep-classification'>")
        .append(HtmlEscaper.escape(classificationLabel(isDirect, roots)))
        .append(DIV_CLOSE);

    if (isDirect) {
      appendDirectRemediation(sb, result, fixedVerStr);
    }

    if (!roots.isEmpty()) {
      if (isDirect) {
        sb.append("<hr style='border: 0; border-top: 1px solid #ccc; margin: 8px 0;'/>");
      }
      appendTransitiveRemediation(sb, result, fixedVerStr, roots);
    }
    sb.append(DIV_CLOSE);
  }

  private boolean isDirectDependency(Set<List<String>> chains, Set<String> roots) {
    if (chains.isEmpty()) {
      return true;
    }
    // Compute roots explicitly: a stream peek() side-effect is not guaranteed to run for every
    // element when anyMatch() short-circuits, which would silently drop transitive roots.
    boolean direct = false;
    for (List<String> chain : chains) {
      if (chain.size() > 1) {
        roots.add(chain.getFirst());
      } else {
        direct = true;
      }
    }
    return direct;
  }

  private void appendDirectRemediation(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result, String fixedVerStr) {
    if (!UNKNOWN.equals(fixedVerStr)) {
      sb.append("<p>Upgrade <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append("</b> to version <b>")
          .append(HtmlEscaper.escape(fixedVerStr))
          .append("</b>");
      sb.append(VulnerabilityCardComposer.copyButton(fixedVerStr)).append("</p>");
    } else {
      sb.append("<p>No fixed version available for <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append("</b> at this time.</p>");
    }
  }

  private void appendTransitiveRemediation(
      StringBuilder sb,
      VulnerabilityScannerService.ScanResult result,
      String fixedVerStr,
      Set<String> roots) {
    if (!UNKNOWN.equals(fixedVerStr)) {
      sb.append("<p>For transitive dependencies, upgrade:</p>");
      sb.append("<ul>");
      roots.forEach(
          root -> sb.append("<li><code>").append(HtmlEscaper.escape(root)).append("</code></li>"));
      sb.append("</ul>");
      sb.append("<p>to a version that uses <b>")
          .append(HtmlEscaper.escape(result.pkg().name()))
          .append("</b> version <b>")
          .append(HtmlEscaper.escape(fixedVerStr))
          .append("</b> or later.</p>");
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
        .append(result.vulnerabilities().size() == 1 ? " Vulnerability" : " Vulnerabilities")
        .append(DIV_CLOSE);
    result
        .vulnerabilities()
        .forEach(
            vuln -> {
              sb.append("<div class='card'>");
              sb.append(
                  VulnerabilityCardComposer.vulnCardInner(
                      vuln, result.pkg().name(), result.pkg().version(), true));
              sb.append(DIV_CLOSE);
            });
  }

  private void appendDependencyChains(
      StringBuilder sb, VulnerabilityScannerService.ScanResult result) {
    Set<List<String>> chains = result.pkg().dependencyChains();
    if (!chains.isEmpty()) {
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
        AtomicInteger idx = new AtomicInteger(0);
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

  /** Rebuilds only the body: the ~10 KB CSS/theme shell is built once per theme and reused. */
  private String generateHtml(String bodyContent) {
    boolean isDark = ColorUtil.isDark(UIUtil.getPanelBackground());
    return htmlShells.computeIfAbsent(isDark, VulnSpotterToolWindow::buildHtmlShell)
        + bodyContent
        + "</body></html>";
  }

  /** Precomputed once per severity (and per theme, via the cache above) instead of per paint. */
  private Icon getSeverityIcon(String s) {
    return severityIcons.computeIfAbsent(s, VulnSpotterToolWindow::resolveSeverityIcon);
  }

  public JComponent getContent() {
    return content;
  }

  /**
   * Scan-lifecycle phases of the panel. One place renders each phase so a new state cannot be added
   * half-way: today three transitions hand-copy the same widget flips. Texts stay outside — the
   * transition callers pass the exact status string, so user-visible wording is unchanged.
   */
  private enum ScanUiPhase {
    SCANNING,
    RESULTS,
    NO_DEPS,
    FAILED,
    CANCELLED;

    void apply(VulnSpotterToolWindow tw, String statusText, boolean exportEnabled) {
      switch (this) {
        case SCANNING -> {
          tw.scanButton.setEnabled(false);
          tw.exportButton.setEnabled(false);
          tw.cancelButton.setVisible(true);
          tw.statusLabel.setText(statusText);
          tw.progressBar.setVisible(true);
          // A new scan is a fresh view: stale results, blobs and query text must not linger.
          tw.tableModel.setRowCount(0);
          tw.scanResults.clear();
          tw.searchBlobs.clear();
          tw.searchField.setText("");
        }
        case RESULTS, NO_DEPS, FAILED, CANCELLED -> {
          tw.scanButton.setEnabled(true);
          tw.cancelButton.setVisible(false);
          tw.exportButton.setEnabled(exportEnabled);
          tw.progressBar.setVisible(false);
          tw.statusLabel.setText(statusText);
        }
      }
    }
  }

  private record HtmlTheme(String bgColor, String textColor, String cardBg, String borderColor) {}

  /** Renders the severity column with a colored icon plus readable text. */
  private final class SeverityCellRenderer extends DefaultTableCellRenderer {
    @Serial private static final long serialVersionUID = 1L;

    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
      super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
      String severity = value == null ? "" : value.toString();
      setIcon(getSeverityIcon(severity));
      String display = displayName(severity);
      setText(display);
      setToolTipText(display);
      return this;
    }

    private String displayName(String severity) {
      if (severity.isEmpty()) return "";
      if (SeverityAnalyzer.SAFE.equals(severity)) return "Safe";
      return severity.charAt(0) + severity.substring(1).toLowerCase(Locale.ROOT);
    }
  }
}
