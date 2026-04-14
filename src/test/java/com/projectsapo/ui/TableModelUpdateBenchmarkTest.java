/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.VulnSpotter.ui;

import java.util.Vector;
import javax.swing.table.DefaultTableModel;
import org.junit.jupiter.api.Test;

public class TableModelUpdateBenchmarkTest {

  private static final int ROW_COUNT = 10000;
  private static final String[] COLUMN_NAMES = {"Severity", "Dependency", "Version", "Vulns"};

  @Test
  public void benchmarkTableModelUpdates() {
    // Baseline: Individual addRow calls
    long startIndividual = System.nanoTime();
    runIndividualUpdates();
    long durationIndividual = System.nanoTime() - startIndividual;

    // Optimized: Bulk update using setDataVector
    long startBulk = System.nanoTime();
    runBulkUpdates();
    long durationBulk = System.nanoTime() - startBulk;

    System.out.printf("Individual addRow: %.2f ms%n", durationIndividual / 1_000_000.0);
    System.out.printf("Bulk update (direct Vector): %.2f ms%n", durationBulk / 1_000_000.0);
    System.out.printf("Improvement: %.2fx%n", (double) durationIndividual / durationBulk);
  }

  private void runIndividualUpdates() {
    DefaultTableModel model = new DefaultTableModel(COLUMN_NAMES, 0);
    for (int i = 0; i < ROW_COUNT; i++) {
      model.addRow(new Object[] {"HIGH", "pkg-" + i, "1.0." + i, i});
    }
  }

  @SuppressWarnings("unchecked")
  private void runBulkUpdates() {
    DefaultTableModel model = new DefaultTableModel(COLUMN_NAMES, 0);
    Vector<Vector<Object>> dataVector = (Vector) model.getDataVector();
    int firstRow = dataVector.size();
    for (int i = 0; i < ROW_COUNT; i++) {
      Vector<Object> row = new Vector<>(4);
      row.add("HIGH");
      row.add("pkg-" + i);
      row.add("1.0." + i);
      row.add(i);
      dataVector.add(row);
    }
    if (ROW_COUNT > 0) {
      model.fireTableRowsInserted(firstRow, dataVector.size() - 1);
    }
  }
}
