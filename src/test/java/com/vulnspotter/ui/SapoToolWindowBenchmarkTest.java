/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.vulnspotter.ui;

import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SapoToolWindowBenchmarkTest {

  private static final NumberFormat STATIC_FORMAT = NumberFormat.getInstance(Locale.ROOT);
  private static final ThreadLocal<NumberFormat> THREAD_LOCAL_FORMAT =
      ThreadLocal.withInitial(() -> NumberFormat.getInstance(Locale.ROOT));
  private static final int ITERATIONS = 100000;
  private static final String SCORE = "7.5";

  private static final String REGEX = "Fixed(?:<[^>]+>|\\s){1,100}(\\d+\\.\\d+(?:\\.\\d+)?)";
  private static final Pattern PRECOMPILED_PATTERN =
      Pattern.compile(REGEX, Pattern.CASE_INSENSITIVE);
  private static final String HTML_SAMPLE =
      "<div>Some text here</div><span>Fixed</span>  <br> 1.2.3 and more text";

  @Test
  public void benchmarkNumberFormatPerformance() throws ParseException {
    // Warmup
    for (int i = 0; i < 1000; i++) {
      runUnoptimizedNumberFormat();
      runStaticNumberFormat();
      runThreadLocalNumberFormat();
    }

    // Unoptimized run
    long startUnopt = System.nanoTime();
    for (int i = 0; i < ITERATIONS; i++) {
      runUnoptimizedNumberFormat();
    }
    long durationUnopt = System.nanoTime() - startUnopt;

    // Static run
    long startStatic = System.nanoTime();
    for (int i = 0; i < ITERATIONS; i++) {
      runStaticNumberFormat();
    }
    long durationStatic = System.nanoTime() - startStatic;

    // ThreadLocal run
    long startTL = System.nanoTime();
    for (int i = 0; i < ITERATIONS; i++) {
      runThreadLocalNumberFormat();
    }
    long durationTL = System.nanoTime() - startTL;

    System.out.printf(
        "NumberFormat - Unoptimized (new instance): %.2f ms%n", durationUnopt / 1_000_000.0);
    System.out.printf(
        "NumberFormat - Static instance:           %.2f ms%n", durationStatic / 1_000_000.0);
    System.out.printf(
        "NumberFormat - ThreadLocal instance:      %.2f ms%n", durationTL / 1_000_000.0);

    double improvement = (double) durationUnopt / durationTL;
    System.out.printf("NumberFormat - ThreadLocal Speedup: %.2fx%n", improvement);

    // Assert that ThreadLocal is significantly faster than unoptimized
    Assertions.assertTrue(durationTL < durationUnopt, "ThreadLocal version should be faster");
  }

  @Test
  public void benchmarkRegexCompilation() {
    // Warmup
    for (int i = 0; i < 1000; i++) {
      runUnoptimizedRegex();
      runOptimizedRegex();
    }

    // Unoptimized run (Recompiling every time)
    long startUnopt = System.nanoTime();
    for (int i = 0; i < ITERATIONS; i++) {
      runUnoptimizedRegex();
    }
    long durationUnopt = System.nanoTime() - startUnopt;

    // Optimized run (Using precompiled pattern)
    long startOpt = System.nanoTime();
    for (int i = 0; i < ITERATIONS; i++) {
      runOptimizedRegex();
    }
    long durationOpt = System.nanoTime() - startOpt;

    System.out.printf("Regex - Unoptimized (Recompile): %.2f ms%n", durationUnopt / 1_000_000.0);
    System.out.printf("Regex - Optimized (Precompiled): %.2f ms%n", durationOpt / 1_000_000.0);

    double improvement = (double) durationUnopt / durationOpt;
    System.out.printf("Regex Speedup: %.2fx%n", improvement);

    // Assert that Optimized is faster than unoptimized
    Assertions.assertTrue(durationOpt < durationUnopt, "Precompiled version should be faster");
  }

  private void runUnoptimizedNumberFormat() throws ParseException {
    NumberFormat.getInstance(Locale.ROOT).parse(SCORE).doubleValue();
  }

  private void runStaticNumberFormat() throws ParseException {
    STATIC_FORMAT.parse(SCORE).doubleValue();
  }

  private void runThreadLocalNumberFormat() throws ParseException {
    THREAD_LOCAL_FORMAT.get().parse(SCORE).doubleValue();
  }

  private void runUnoptimizedRegex() {
    Pattern p = Pattern.compile(REGEX, Pattern.CASE_INSENSITIVE);
    Matcher m = p.matcher(HTML_SAMPLE);
    if (m.find()) {
      m.group(1);
    }
  }

  private void runOptimizedRegex() {
    Matcher m = PRECOMPILED_PATTERN.matcher(HTML_SAMPLE);
    if (m.find()) {
      m.group(1);
    }
  }
}
