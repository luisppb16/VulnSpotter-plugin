/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.projectsapo.benchmark;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.projectsapo.model.OsvPackage;
import com.projectsapo.util.PackageKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Benchmark comparing String concatenation vs Record key for grouping. */
public class GroupingBenchmarkTest {

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

    // Warmup
    runStringConcat(packages);
    runRecordKey(packages);

    // Benchmark String Concat
    long startString = System.nanoTime();
    for (int i = 0; i < 10; i++) {
      runStringConcat(packages);
    }
    long durationString = System.nanoTime() - startString;

    // Benchmark Record Key
    long startRecord = System.nanoTime();
    for (int i = 0; i < 10; i++) {
      runRecordKey(packages);
    }
    long durationRecord = System.nanoTime() - startRecord;

    System.out.printf("String Concat Duration: %.2f ms%n", durationString / 1_000_000.0);
    System.out.printf("Record Key Duration:    %.2f ms%n", durationRecord / 1_000_000.0);
    System.out.printf(
        "Improvement:            %.2f%%%n", (1.0 - (double) durationRecord / durationString) * 100);

    // Verify Record is not significantly slower (it should be faster)
    // Note: In some microbenchmarks with simple strings, the difference might be small,
    // but allocation-wise Record is better.
    // We assert that it's at least within 120% of string time (allowing some noise) but ideally
    // faster.
    // If the improvement is negative, it means Record is slower.

    // However, for the purpose of this task, we expect it to be faster or comparable.
    assertTrue(
        durationRecord < durationString * 1.2, "Record key should not be significantly slower");
  }

  private void runStringConcat(List<OsvPackage> packages) {
    Map<String, List<OsvPackage>> grouped =
        packages.stream()
            .collect(
                Collectors.groupingBy(
                    pkg -> pkg.name() + ":" + pkg.version() + ":" + pkg.ecosystem()));
  }

  private void runRecordKey(List<OsvPackage> packages) {
    Map<PackageKey, List<OsvPackage>> grouped =
        packages.stream()
            .collect(
                Collectors.groupingBy(
                    pkg -> new PackageKey(pkg.name(), pkg.version(), pkg.ecosystem())));
  }
}
