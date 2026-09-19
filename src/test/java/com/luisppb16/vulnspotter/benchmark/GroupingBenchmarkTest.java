/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.benchmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.domain.model.PackageKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * Benchmark comparing String concatenation vs Record key for grouping.
 *
 * <p>Both implementations alternate within each measured round so JIT/GC state affects both the
 * same way; a single-block comparison is order-biased and can swing the result by tens of percent.
 */
public class GroupingBenchmarkTest {

  private static final int WARMUP_ROUNDS = 5;
  private static final int MEASURED_ROUNDS = 20;

  @Test
  public void benchmarkGrouping() {
    // Setup
    int packageCount = 100_000;
    List<OsvPackage> packages = new ArrayList<>(packageCount);
    for (int i = 0; i < packageCount; i++) {
      // Generate some duplicates
      int id = i % (packageCount / 10);
      packages.add(new OsvPackage("pkg-" + id, "Maven", "1.0." + id));
    }

    // Groupings must be equivalent; otherwise the benchmark compares different work
    assertGroupingsEquivalent(packages);

    // Warmup, alternating both implementations
    for (int round = 0; round < WARMUP_ROUNDS; round++) {
      runStringConcat(packages);
      runRecordKey(packages);
    }

    // Measured rounds, alternating to cancel JIT/GC drift
    long durationString = 0;
    long durationRecord = 0;
    for (int round = 0; round < MEASURED_ROUNDS; round++) {
      long startString = System.nanoTime();
      runStringConcat(packages);
      durationString += System.nanoTime() - startString;

      long startRecord = System.nanoTime();
      runRecordKey(packages);
      durationRecord += System.nanoTime() - startRecord;
    }

    double stringMs = durationString / 1_000_000.0;
    double recordMs = durationRecord / 1_000_000.0;
    System.out.printf("String Concat Duration: %.2f ms%n", stringMs);
    System.out.printf("Record Key Duration:    %.2f ms%n", recordMs);
    System.out.printf("Improvement:            %.2f%%%n", (1.0 - recordMs / stringMs) * 100);

    assertTrue(recordMs < stringMs * 1.2, "Record key should not be significantly slower");
  }

  private void assertGroupingsEquivalent(List<OsvPackage> packages) {
    Map<String, List<OsvPackage>> byString = runStringConcat(packages);
    Map<PackageKey, List<OsvPackage>> byRecord = runRecordKey(packages);

    assertEquals(byString.size(), byRecord.size(), "Group count must match");
    byString.forEach(
        (key, expected) -> {
          String[] parts = key.split(":", 3);
          List<OsvPackage> actual = byRecord.get(new PackageKey(parts[0], parts[1], parts[2]));
          assertEquals(expected, actual, "Group " + key + " must contain the same packages");
        });
  }

  private Map<String, List<OsvPackage>> runStringConcat(List<OsvPackage> packages) {
    return packages.stream()
        .collect(
            Collectors.groupingBy(pkg -> pkg.name() + ":" + pkg.version() + ":" + pkg.ecosystem()));
  }

  private Map<PackageKey, List<OsvPackage>> runRecordKey(List<OsvPackage> packages) {
    return packages.stream()
        .collect(
            Collectors.groupingBy(
                pkg -> new PackageKey(pkg.name(), pkg.version(), pkg.ecosystem())));
  }
}
