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
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
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
import com.intellij.ui.jcef.JBCefApp;
import com.intellij.ui.jcef.JBCefBrowser;
import com.intellij.ui.jcef.JBCefClient;
import com.intellij.ui.table.JBTable;
import com.intellij.util.IconUtil;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.luisppb16.vulnspotter.application.service.VulnerabilityScannerService;
import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.domain.service.FixedVersionResolver;
import com.luisppb16.vulnspotter.domain.service.SeverityAnalyzer;
import com.luisppb16.vulnspotter.infrastructure.report.ReportExportService;
import com.luisppb16.vulnspotter.infrastructure.report.VulnerabilityReportBuilder;
import com.luisppb16.vulnspotter.util.HtmlEscaper;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.Serial;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import org.cef.browser.CefBrowser;
import org.cef.browser.CefFrame;
import org.cef.handler.CefRequestHandlerAdapter;
import org.cef.network.CefRequest;

/**
 * Tool window UI for VulnSpotter: results table with severity ranking plus an HTML details panel
 * (JCEF when available, Swing fallback otherwise).
 */
public final class VulnSpotterToolWindow implements Disposable {

  private static final String UNKNOWN = FixedVersionResolver.UNKNOWN;
  private static final String DIV_CLOSE = "</div>";
  private static final JBColor COLOR_CRITICAL = new JBColor(0xB71C1C, 0xEF5350);
  private static final JBColor COLOR_HIGH = new JBColor(0xE65100, 0xFFA726);
  private static final JBColor COLOR_MEDIUM = new JBColor(0xF57F17, 0xFFEE58);
  private static final JBColor COLOR_LOW = new JBColor(0x33691E, 0x9CCC65);
  private static final long SCAN_TIMEOUT_SECONDS = 300;

  /**
   * Resolves whether JCEF is available for the HTML details panel. Defaults to {@link
   * JBCefApp#isSupported()} but is package-private and mutable so unit tests can force the Swing
   * {@code JEditorPane} fallback without loading JCEF's static initializer, which needs the
   * application {@code RegistryManager} service that is absent under a mock application. A method
   * reference does not initialize the referenced class, so assigning it here is safe.
   */
  static volatile BooleanSupplier jcefSupported = JBCefApp::isSupported;

  private final JPanel content;
  private final CardLayout cardLayout = new CardLayout();
  private final JPanel mainPanel;
  private final JBTable resultsTable;
  private final DefaultTableModel tableModel;
  private final JBCefBrowser browser; // null when JCEF is unavailable
  private final JEditorPane fallbackPane; // used when JCEF is unavailable
  private final Project project;
  private final JButton scanButton;
  private final JButton cancelButton;
  private final JButton exportButton;
  private final JLabel statusLabel;
  private final SearchTextField searchField;
  private final JBCheckBox vulnerableOnlyCheckbox;
  private final JProgressBar progressBar;
  private final List<VulnerabilityScannerService.ScanResult> scanResults = new ArrayList<>();
  private final SeverityAnalyzer severityAnalyzer = new SeverityAnalyzer();
  private volatile CompletableFuture<List<VulnerabilityScannerService.ScanResult>> activeScan;

  public VulnSpotterToolWindow(Project project) {
    this.project = project;
    this.content = new JPanel(new BorderLayout());

    if (jcefSupported.getAsBoolean()) {
      this.browser = new JBCefBrowser();
      this.fallbackPane = null;
      Disposer.register(this, browser);

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
    } else {
      this.browser = null;
      JEditorPane pane = new JEditorPane();
      pane.setContentType("text/html");
      pane.setEditable(false);
      pane.addHyperlinkListener(
          e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED
                && e.getURL() != null) {
              BrowserUtil.browse(e.getURL());
            }
          });
      this.fallbackPane = pane;
    }

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

    TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
    sorter.setComparator(
        0, Comparator.comparingInt(sev -> SeverityAnalyzer.severityToLevel((String) sev)));
    resultsTable.setRowSorter(sorter);
    // Most severe first, then alphabetically by dependency
    sorter.setSortKeys(
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
                int row = resultsTable.getSelectedRow();
                if (row >= 0) {
                  int modelRow = resultsTable.convertRowIndexToModel(row);
                  if (modelRow < scanResults.size()) {
                    showDetails(scanResults.get(modelRow));
                  }
                }
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
    splitter.setSecondComponent(
        browser != null ? browser.getComponent() : new JBScrollPane(fallbackPane));

    mainPanel = new JPanel(cardLayout);
    mainPanel.add(createEmptyStatePanel(), "EMPTY");
    mainPanel.add(splitter, "RESULTS");

    content.add(mainPanel, BorderLayout.CENTER);
    cardLayout.show(mainPanel, "EMPTY");

    loadDetailsHtml(
        generateHtml("<h1>VulnSpotter</h1><p>Select a dependency to see details.</p>"));

    // Re-render the details panel when the IDE theme changes
    ApplicationManager.getApplication()
        .getMessageBus()
        .connect(this)
        .subscribe(
            LafManagerListener.TOPIC,
            (LafManagerListener)
                source -> {
                  int row = resultsTable.getSelectedRow();
                  if (row >= 0) {
                    int modelRow = resultsTable.convertRowIndexToModel(row);
                    if (modelRow < scanResults.size()) {
                      showDetails(scanResults.get(modelRow));
                      return;
                    }
                  }
                  loadDetailsHtml(
                      generateHtml(
                          "<h1>VulnSpotter</h1><p>Select a dependency to see details.</p>"));
                });
  }

  @Override
  public void dispose() {
    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> scan = activeScan;
    if (scan != null) {
      scan.cancel(true);
    }
  }

  private void loadDetailsHtml(String html) {
    if (browser != null) {
      browser.loadHTML(html);
    } else if (fallbackPane != null) {
      fallbackPane.setText(html);
      fallbackPane.setCaretPosition(0);
    }
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
                            v ->
                                BrowserUtil.browse(
                                    "https://osv.dev/vulnerability/" + v.id()))));
    menu.add(openOsv);

    // Submenu to open every vulnerability advisory of the selected dependency at once.
    JMenu openAll = new JMenu("Open all vulnerabilities");
    openAll.setIcon(AllIcons.Ide.External_link_arrow);
    openAll.addMenuListener(
        new MenuListener() {
          @Override
          public void menuSelected(MenuEvent e) {
            openAll.removeAll();
            int row = resultsTable.getSelectedRow();
            if (row < 0) return;
            int modelRow = resultsTable.convertRowIndexToModel(row);
            if (modelRow >= scanResults.size()) return;
            VulnerabilityScannerService.ScanResult result = scanResults.get(modelRow);
            for (OsvVulnerability vuln : result.vulnerabilities()) {
              JMenuItem item = new JMenuItem(vuln.id());
              item.addActionListener(
                  ev -> BrowserUtil.browse("https://osv.dev/vulnerability/" + vuln.id()));
              openAll.add(item);
            }
            if (openAll.getItemCount() == 0) {
              openAll.add(new JMenuItem("No vulnerabilities"));
            }
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
                            result.vulnerabilities(),
                            result.pkg().name(),
                            result.pkg().version())
                        .ifPresent(
                            fix ->
                                CopyPasteManager.getInstance()
                                    .setContents(new StringSelection(fix)))));
    menu.add(copyFix);

    JMenuItem copySnippet = new JMenuItem("Copy Upgrade Snippet");
    copySnippet.setToolTipText(
        "Copy a manifest snippet that pins the recommended fixed version.");
    copySnippet.addActionListener(
        e ->
            withSelectedResult(
                result ->
                    FixedVersionResolver.recommendUpgrade(
                            result.vulnerabilities(),
                            result.pkg().name(),
                            result.pkg().version())
                        .ifPresent(
                            fix ->
                                CopyPasteManager.getInstance()
                                    .setContents(
                                        new StringSelection(
                                            buildUpgradeSnippet(result, fix))))));
    menu.add(copySnippet);

    menu.addSeparator();

    JMenuItem ignore = new JMenuItem("Ignore this Dependency", AllIcons.Actions.Cancel);
    ignore.addActionListener(e -> withSelectedResult(this::ignoreDependency));
    menu.add(ignore);

    return menu;
  }

  /** Builds an ecosystem-appropriate manifest snippet pinning the fixed version. */
  private static String buildUpgradeSnippet(
      VulnerabilityScannerService.ScanResult result, String fix) {
    String name = result.pkg().name();
    String ecosystem = result.pkg().ecosystem();
    if (ecosystem == null) {
      return name + ":" + fix;
    }
    return switch (ecosystem) {
      case "Maven" -> {
        int colon = name.indexOf(':');
        String group = colon >= 0 ? name.substring(0, colon) : name;
        String artifact = colon >= 0 ? name.substring(colon + 1) : name;
        yield "<dependency>\n"
            + "  <groupId>"
            + group
            + "</groupId>\n"
            + "  <artifactId>"
            + artifact
            + "</artifactId>\n"
            + "  <version>"
            + fix
            + "</version>\n"
            + "</dependency>";
      }
      case "npm" -> "npm install " + name + "@" + fix;
      case "PyPI" -> name + "==" + fix;
      case "Go" -> name + " v" + fix;
      default -> name + ":" + fix;
    };
  }

  private void ignoreDependency(VulnerabilityScannerService.ScanResult result) {
    String entry = result.pkg().name();
    ApplicationManager.getApplication()
        .executeOnPooledThread(
            () -> {
              try {
                String base = project.getBasePath();
                if (base == null) {
                  return;
                }
                Path ignoreFile = Paths.get(base, ".vulnspotterignore");
                String line = entry + System.lineSeparator();
                if (Files.exists(ignoreFile)) {
                  Files.writeString(ignoreFile, line,
                      StandardOpenOption.APPEND);
                } else {
                  Files.writeString(ignoreFile, line,
                      StandardOpenOption.CREATE);
                }
                ApplicationManager.getApplication()
                    .invokeLater(
                        () ->
                            NotificationGroupManager.getInstance()
                                .getNotificationGroup("VulnSpotter Notifications")
                                .createNotification(
                                    "VulnSpotter",
                                    "Added \""
                                        + entry
                                        + "\" to .vulnspotterignore. Re-scan to apply.",
                                    NotificationType.INFORMATION)
                                .notify(project),
                        project.getDisposed());
              } catch (IOException ex) {
                ApplicationManager.getApplication()
                    .invokeLater(
                        () ->
                            NotificationGroupManager.getInstance()
                                .getNotificationGroup("VulnSpotter Notifications")
                                .createNotification(
                                    "VulnSpotter",
                                    "Could not update .vulnspotterignore: " + ex.getMessage(),
                                    NotificationType.ERROR)
                                .notify(project),
                        project.getDisposed());
              }
            });
  }

  private void withSelectedResult(
      Consumer<VulnerabilityScannerService.ScanResult> consumer) {
    int row = resultsTable.getSelectedRow();
    if (row < 0) return;
    int modelRow = resultsTable.convertRowIndexToModel(row);
    if (modelRow < scanResults.size()) {
      consumer.accept(scanResults.get(modelRow));
    }
  }

  private void applyFilters() {
    @SuppressWarnings("unchecked")
    TableRowSorter<DefaultTableModel> sorter =
        (TableRowSorter<DefaultTableModel>) resultsTable.getRowSorter();
    if (sorter == null) return;

    String searchText = searchField.getText().toLowerCase(Locale.ROOT);
    boolean vulnerableOnly = vulnerableOnlyCheckbox.isSelected();
    boolean hasSearch = !searchText.isEmpty();

    sorter.setRowFilter(
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
            String name = entry.getStringValue(1).toLowerCase(Locale.ROOT);
            if (name.contains(searchText)) {
              return true;
            }
            // Also match CVE aliases and vulnerability ids so users can search "CVE-2024-1234".
            int modelRow = entry.getIdentifier();
            if (modelRow >= 0 && modelRow < scanResults.size()) {
              VulnerabilityScannerService.ScanResult result = scanResults.get(modelRow);
              for (OsvVulnerability vuln : result.vulnerabilities()) {
                if (vuln.id() != null && vuln.id().toLowerCase(Locale.ROOT).contains(searchText)) {
                  return true;
                }
                if (vuln.aliases() != null) {
                  for (String alias : vuln.aliases()) {
                    if (alias != null
                        && alias.toLowerCase(Locale.ROOT).contains(searchText)) {
                      return true;
                    }
                  }
                }
              }
            }
            return false;
          }
        });

    updateEmptyText();
  }

  private void updateEmptyText() {
    if (scanResults.isEmpty()) {
      resultsTable.getEmptyText().setText("No results");
      return;
    }
    long vulnerable = scanResults.stream().filter(r -> r.vulnerable()).count();
    if (vulnerableOnlyCheckbox.isSelected() && vulnerable == 0) {
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
    scanButton.setEnabled(false);
    exportButton.setEnabled(false);
    cancelButton.setVisible(true);
    statusLabel.setText("Scanning...");
    progressBar.setVisible(true);
    tableModel.setRowCount(0);
    scanResults.clear();
    // A new scan is a fresh view: drop any leftover search query so results are not hidden.
    searchField.setText("");

    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> future =
        VulnerabilityScannerService.getInstance(project)
            .scanDependencies()
            .orTimeout(SCAN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    activeScan = future;

    future
        .thenAccept(
            results ->
                ApplicationManager.getApplication()
                    .invokeLater(() -> onScanFinished(results), project.getDisposed()))
        .exceptionally(
            ex -> {
              ApplicationManager.getApplication()
                  .invokeLater(() -> onScanFailed(ex), project.getDisposed());
              return null;
            });
  }

  private void cancelScan() {
    CompletableFuture<List<VulnerabilityScannerService.ScanResult>> scan = activeScan;
    if (scan != null) {
      scan.cancel(true);
    }
  }

  private void onScanFinished(List<VulnerabilityScannerService.ScanResult> results) {
    activeScan = null;
    scanResults.addAll(results);
    VulnerabilityScannerService.getInstance(project).updateResults(results);

    long vulnerableCount = results.stream().filter(r -> r.vulnerable()).count();
    results.forEach(
        result -> {
          String highestSev =
              result.vulnerable()
                  ? severityAnalyzer.getHighestSeverity(result.vulnerabilities())
                  : SeverityAnalyzer.SAFE;
          String fixedVer =
              result.vulnerable()
                  ? FixedVersionResolver.recommendUpgrade(
                          result.vulnerabilities(), result.pkg().name(), result.pkg().version())
                      .orElse(UNKNOWN)
                  : "";
          tableModel.addRow(
              new Object[] {
                highestSev,
                result.pkg().name(),
                result.pkg().version(),
                fixedVer,
                result.vulnerabilities().size()
              });
        });

    if (!results.isEmpty()) {
      cardLayout.show(mainPanel, "RESULTS");
      statusLabel.setText(
          vulnerableCount + " vulnerable of " + results.size() + " dependencies scanned");
      if (vulnerableCount > 0) {
        NotificationGroupManager.getInstance()
            .getNotificationGroup("VulnSpotter Notifications")
            .createNotification(
                "VulnSpotter found vulnerabilities",
                vulnerableCount
                    + " vulnerable dependenc"
                    + (vulnerableCount == 1 ? "y" : "ies")
                    + " of "
                    + results.size()
                    + " scanned. Open the VulnSpotter tool window for remediation advice.",
                NotificationType.WARNING)
            .notify(project);
      }
    } else {
      statusLabel.setText("No dependencies found — make sure the project is synced");
    }

    scanButton.setEnabled(true);
    cancelButton.setVisible(false);
    exportButton.setEnabled(!results.isEmpty());
    progressBar.setVisible(false);
    applyFilters();
  }

  private void onScanFailed(Throwable ex) {
    activeScan = null;
    scanButton.setEnabled(true);
    cancelButton.setVisible(false);
    exportButton.setEnabled(false);
    progressBar.setVisible(false);

    Throwable cause = ex instanceof CompletionException && ex.getCause() != null ? ex.getCause() : ex;
    if (cause instanceof CancellationException) {
      statusLabel.setText("Scan cancelled");
      return;
    }
    String message;
    if (cause instanceof TimeoutException) {
      message =
          "The scan timed out after " + SCAN_TIMEOUT_SECONDS + "s. Try again or narrow the project.";
    } else {
      message =
          cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
    }
    statusLabel.setText("Scan failed: " + message);
    NotificationGroupManager.getInstance()
        .getNotificationGroup("VulnSpotter Notifications")
        .createNotification(
            "VulnSpotter scan failed",
            "The vulnerability scan could not be completed: " + message,
            NotificationType.ERROR)
        .notify(project);
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
                              ex.getMessage() != null
                                  ? ex.getMessage()
                                  : ex.getClass().getSimpleName();
                          statusLabel.setText("Export failed: " + message);
                          NotificationGroupManager.getInstance()
                              .getNotificationGroup("VulnSpotter Notifications")
                              .createNotification(
                                  "VulnSpotter export failed", message, NotificationType.ERROR)
                              .notify(project);
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

  private String appendEscapedWithLineBreaks(String value) {
    if (value == null) {
      return "";
    }
    return HtmlEscaper.escape(value).replace("\n", "<br/>");
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
    boolean hasFix = recommended != null;
    String fixedVerStr = hasFix ? recommended : UNKNOWN;

    sb.append("<div class='dep-classification'>")
        .append(HtmlEscaper.escape(classificationLabel(isDirect, roots)))
        .append(DIV_CLOSE);

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

  private static String classificationLabel(boolean isDirect, Set<String> roots) {
    if (isDirect && roots.isEmpty()) {
      return "Direct dependency";
    }
    if (!isDirect) {
      return "Transitive dependency";
    }
    return "Direct and transitive dependency";
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
          .append("</b>");
      sb.append(" <button class='copy-btn' onclick=\"copyToClipboard('")
          .append(HtmlEscaper.escape(HtmlEscaper.escapeJsSingleQuoted(fixedVerStr)))
          .append("')\">Copy</button></p>");
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
              String sev = severityAnalyzer.getSeverity(vuln);
              Double score = severityAnalyzer.getBaseScore(vuln);
              String fixedV =
                  FixedVersionResolver.resolve(
                      vuln, result.pkg().name(), result.pkg().version());

              sb.append("<div class='card'>");
              sb.append("<div class='card-header'>");
              sb.append("<span class='badge ")
                  .append(HtmlEscaper.escape(sev.toLowerCase(Locale.ROOT)))
                  .append("'>")
                  .append(HtmlEscaper.escape(sev))
                  .append("</span>");
              if (score != null) {
                sb.append("<span class='cvss-score'>CVSS ")
                    .append(String.format(Locale.ROOT, "%.1f", score))
                    .append("</span>");
              }
              sb.append("<span class='vuln-id'><a href='https://osv.dev/vulnerability/")
                  .append(HtmlEscaper.escape(vuln.id()))
                  .append("'>")
                  .append(HtmlEscaper.escape(vuln.id()))
                  .append("</a></span>");
              appendCveAliases(sb, vuln);
              sb.append(DIV_CLOSE);
              sb.append("<div class='vuln-summary'>")
                  .append(
                      vuln.summary() != null ? HtmlEscaper.escape(vuln.summary()) : "No summary")
                  .append(DIV_CLOSE);
              List<String> ranges =
                  FixedVersionResolver.affectedRanges(vuln, result.pkg().name());
              if (!ranges.isEmpty()) {
                sb.append("<div class='affected-range'>Affected: ")
                    .append(HtmlEscaper.escape(String.join(", ", ranges)))
                    .append(DIV_CLOSE);
              }
              sb.append("<div class='fixed-box'>Fixed in: <span class='fixed-ver'>")
                  .append(HtmlEscaper.escape(fixedV))
                  .append("</span>");
              if (!UNKNOWN.equals(fixedV)) {
                sb.append(" <button class='copy-btn' onclick=\"copyToClipboard('")
                    .append(HtmlEscaper.escape(HtmlEscaper.escapeJsSingleQuoted(fixedV)))
                    .append("')\">Copy</button>");
              }
              sb.append(DIV_CLOSE);
              if (vuln.details() != null && !vuln.details().isBlank()) {
                sb.append("<div class='details'>")
                    .append(appendEscapedWithLineBreaks(vuln.details()))
                    .append(DIV_CLOSE);
              }

              if (vuln.references() != null && !vuln.references().isEmpty()) {
                sb.append("<div class='references-section'>");
                sb.append("<div class='references-title'>References</div>");
                vuln.references().stream()
                    .filter(ref -> isSafeUrl(ref.url()))
                    .forEach(
                        ref -> {
                          String url = ref.url();
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

  private void appendCveAliases(StringBuilder sb, OsvVulnerability vuln) {
    if (vuln.aliases() == null) {
      return;
    }
    vuln.aliases().stream()
        .filter(a -> a != null && a.toUpperCase(Locale.ROOT).startsWith("CVE-"))
        .forEach(
            cve ->
                sb.append("<span class='cve-alias'><a href='https://nvd.nist.gov/vuln/detail/")
                    .append(HtmlEscaper.escape(cve))
                    .append("'>")
                    .append(HtmlEscaper.escape(cve))
                    .append("</a></span>"));
  }

  /** Only http(s) links are rendered; javascript:/file: URLs from advisories are dropped. */
  private static boolean isSafeUrl(String url) {
    if (url == null || url.isBlank()) {
      return false;
    }
    String lower = url.trim().toLowerCase(Locale.ROOT);
    return lower.startsWith("http://") || lower.startsWith("https://");
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
        + ".critical { background: #d32f2f; } .high { background: #f57c00; } .medium { background: #fbc02d; color: #333; } .low { background: #43a047; } .unknown { background: #546e7a; }"
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

  private Icon getSeverityIcon(String s) {
    return switch (s) {
      case SeverityAnalyzer.CRITICAL -> IconUtil.colorize(AllIcons.General.Error, COLOR_CRITICAL);
      case SeverityAnalyzer.HIGH -> IconUtil.colorize(AllIcons.General.Warning, COLOR_HIGH);
      case SeverityAnalyzer.MEDIUM -> IconUtil.colorize(AllIcons.General.Note, COLOR_MEDIUM);
      case SeverityAnalyzer.LOW -> IconUtil.colorize(AllIcons.General.Information, COLOR_LOW);
      case SeverityAnalyzer.UNKNOWN -> AllIcons.General.QuestionDialog;
      default -> IconUtil.colorize(AllIcons.General.InspectionsOK, COLOR_LOW);
    };
  }

  public JComponent getContent() {
    return content;
  }

  /** Renders the severity column with a colored icon plus readable text. */
  private final class SeverityCellRenderer extends DefaultTableCellRenderer {
    @Serial private static final long serialVersionUID = 1L;

    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
      super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
      String severity = value == null ? "" : value.toString();
      setIcon(getSeverityIcon(severity));
      setText(displayName(severity));
      setToolTipText(displayName(severity));
      return this;
    }

    private String displayName(String severity) {
      if (severity.isEmpty()) return "";
      if (SeverityAnalyzer.SAFE.equals(severity)) return "Safe";
      return severity.charAt(0) + severity.substring(1).toLowerCase(Locale.ROOT);
    }
  }

  private record HtmlTheme(String bgColor, String textColor, String cardBg, String borderColor) {}
}
