/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("VersionUtil Test Suite")
class VersionUtilTest {

  @Nested
  @DisplayName("compareVersions")
  class CompareVersions {

    @ParameterizedTest(name = "{0} < {1}")
    @CsvSource({
      "1.0.0-alpha, 1.0.0",
      "1.0.0-beta, 1.0.0-rc1",
      "2.0.0-RC1, 2.0.0",
      "1.0-SNAPSHOT, 1.0",
      "1.0.0.Beta2, 1.0.0.Beta10",
      "1.0.0.M1, 1.0.0.RC1",
      "1.9.9, 1.10.0",
      "2.9, 2.10",
      "1.0.0, 1.0.0.sp1",
      "1.0.0-alpha, 1.0.0-beta",
      "5.3.8, 5.3.9.RELEASE",
      "1.0.0, 2.0.0",
    })
    void lessThan(String smaller, String bigger) {
      assertThat(VersionUtil.compareVersions(smaller, bigger)).isNegative();
      assertThat(VersionUtil.compareVersions(bigger, smaller)).isPositive();
    }

    @ParameterizedTest(name = "{0} == {1}")
    @CsvSource({
      "5.3.9.RELEASE, 5.3.9",
      "2.0.0.Final, 2.0.0",
      "1.0-ga, 1.0",
      "1.0.0, 1.0",
      "1.0.0, 1",
      "1.0.0-CR1, 1.0.0-rc1",
      "1.0.0-a1, 1.0.0-alpha-1",
    })
    void equalTo(String v1, String v2) {
      assertThat(VersionUtil.compareVersions(v1, v2)).isZero();
    }
  }

  @Nested
  @DisplayName("isPrerelease")
  class IsPrerelease {

    @Test
    void detectsPrereleaseQualifiers() {
      assertThat(VersionUtil.isPrerelease("1.0.0-alpha")).isTrue();
      assertThat(VersionUtil.isPrerelease("2.0.0-RC1")).isTrue();
      assertThat(VersionUtil.isPrerelease("1.0-SNAPSHOT")).isTrue();
      assertThat(VersionUtil.isPrerelease("3.0.0-M2")).isTrue();
    }

    @Test
    void stableVersionsAreNotPrerelease() {
      assertThat(VersionUtil.isPrerelease("1.0.0")).isFalse();
      assertThat(VersionUtil.isPrerelease("5.3.9.RELEASE")).isFalse();
      assertThat(VersionUtil.isPrerelease("2.0.0.Final")).isFalse();
      assertThat(VersionUtil.isPrerelease("1.0.0.sp1")).isFalse();
    }
  }

  @Nested
  @DisplayName("findBestFixedVersion")
  class FindBestFixedVersion {

    @Test
    void picksSmallestVersionGreaterThanCurrent() {
      String best =
          VersionUtil.findBestFixedVersion(List.of("2.17.1", "2.16.0", "3.0.0"), "2.14.0");
      assertThat(best).isEqualTo("2.16.0");
    }

    @Test
    void prefersSameMajorOverLowerCrossMajor() {
      String best = VersionUtil.findBestFixedVersion(List.of("3.0.1", "2.17.2"), "2.14.0");
      assertThat(best).isEqualTo("2.17.2");
    }

    @Test
    void returnsNullWhenNothingIsGreater() {
      assertThat(VersionUtil.findBestFixedVersion(List.of("1.0.0", "1.2.0"), "2.0.0")).isNull();
    }

    @Test
    void prefersStableOverPrerelease() {
      String best = VersionUtil.findBestFixedVersion(List.of("2.0.0-RC1", "2.0.0"), "1.9.0");
      assertThat(best).isEqualTo("2.0.0");
    }

    @Test
    void fallsBackToPrereleaseWhenNoStableFixExists() {
      String best = VersionUtil.findBestFixedVersion(List.of("2.0.0-RC1"), "1.9.0");
      assertThat(best).isEqualTo("2.0.0-RC1");
    }

    @Test
    void handlesNullAndEmptyInputs() {
      assertThat(VersionUtil.findBestFixedVersion(null, "1.0")).isNull();
      assertThat(VersionUtil.findBestFixedVersion(List.of(), "1.0")).isNull();
      assertThat(VersionUtil.findBestFixedVersion(Arrays.asList(null, "", " "), "1.0")).isNull();
    }

    @Test
    void withUnknownCurrentVersionPrefersFirstStable() {
      String best = VersionUtil.findBestFixedVersion(List.of("2.0.0-RC1", "1.5.0", "1.6.0"), null);
      assertThat(best).isEqualTo("1.5.0");
    }
  }
}
