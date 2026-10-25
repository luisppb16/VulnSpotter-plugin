/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.domain.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.luisppb16.vulnspotter.domain.model.OsvVulnerability;
import com.luisppb16.vulnspotter.testsupport.VulnFixtures;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("FixedVersionResolver Test Suite")
class FixedVersionResolverTest {

  /** The real GHSA-7hhh-6rmp-j9qf shape: five affected entries, two package lines. */
  private static OsvVulnerability jacksonCoreAdvisory() {
    OsvVulnerability.Affected comBranch1 =
        VulnFixtures.affectedWithWindows(
            "com.fasterxml.jackson.core:jackson-core",
            List.of(
                VulnFixtures.range(
                    "ECOSYSTEM", List.of(VulnFixtures.event("2.19.0", "2.21.7", null, null)))));
    OsvVulnerability.Affected comBranch2 =
        VulnFixtures.affectedWithWindows(
            "com.fasterxml.jackson.core:jackson-core",
            List.of(
                VulnFixtures.range(
                    "ECOSYSTEM", List.of(VulnFixtures.event("2.22.0", "2.22.3", null, null)))));
    OsvVulnerability.Affected comBranch3 =
        VulnFixtures.affectedWithWindows(
            "com.fasterxml.jackson.core:jackson-core",
            List.of(
                VulnFixtures.range(
                    "ECOSYSTEM", List.of(VulnFixtures.event("2.8.0", "2.18.11", null, null)))));
    OsvVulnerability.Affected toolsBranch1 =
        VulnFixtures.affectedWithWindows(
            "tools.jackson.core:jackson-core",
            List.of(
                VulnFixtures.range(
                    "ECOSYSTEM", List.of(VulnFixtures.event("3.0.0", "3.1.7", null, null)))));
    OsvVulnerability.Affected toolsBranch2 =
        VulnFixtures.affectedWithWindows(
            "tools.jackson.core:jackson-core",
            List.of(
                VulnFixtures.range(
                    "ECOSYSTEM", List.of(VulnFixtures.event("3.2.0", "3.2.3", null, null)))));
    return VulnFixtures.vuln(
        "GHSA-7hhh-6rmp-j9qf",
        "jackson-core DoS",
        null,
        null,
        List.of(comBranch1, comBranch2, comBranch3, toolsBranch1, toolsBranch2),
        null,
        null);
  }

  @Nested
  @DisplayName("affected windows")
  class AffectedWindows {

    @Test
    void keepsEveryWindowOfAnEventList() {
      // Given: ONE range whose event list declares two branches.
      OsvVulnerability.Affected affected =
          VulnFixtures.affectedWithWindows(
              "tools.jackson.core:jackson-core",
              List.of(
                  VulnFixtures.range(
                      "ECOSYSTEM",
                      List.of(
                          VulnFixtures.event("3.0.0", "3.1.7", null, null),
                          VulnFixtures.event("3.2.0", "3.2.3", null, null)))));
      OsvVulnerability vuln =
          VulnFixtures.vuln("GHSA-1", "s", null, null, List.of(affected), null, null);

      // When
      FixedVersionResolver.Resolution resolution =
          FixedVersionResolver.resolveWithRanges(vuln, "tools.jackson.core:jackson-core", "3.1.4");

      // Then: both windows are rendered, each with its own fix.
      assertThat(resolution.branches()).hasSize(2);
      assertThat(resolution.branches().get(0).branchLabel()).isEqualTo("Branch 3.0.x");
      assertThat(resolution.branches().get(0).rangeText()).isEqualTo(">=3.0.0, <3.1.7");
      assertThat(resolution.branches().get(0).fixedVersion()).isEqualTo("3.1.7");
      assertThat(resolution.branches().get(0).containsInstalledVersion()).isTrue();
      assertThat(resolution.branches().get(1).branchLabel()).isEqualTo("Branch 3.2.x");
      assertThat(resolution.branches().get(1).rangeText()).isEqualTo(">=3.2.0, <3.2.3");
      assertThat(resolution.branches().get(1).fixedVersion()).isEqualTo("3.2.3");
      assertThat(resolution.branches().get(1).containsInstalledVersion()).isFalse();
      assertThat(resolution.affectedRanges()).containsExactly(">=3.0.0, <3.1.7", ">=3.2.0, <3.2.3");
      assertThat(resolution.fixedVersion()).isEqualTo("3.1.7");
    }

    @Test
    void scannedToolsJacksonSeesOnlyItsTwoBranches() {
      // When: the scanned package is the Jackson 3 coordinate at 3.1.4.
      FixedVersionResolver.Resolution resolution =
          FixedVersionResolver.resolveWithRanges(
              jacksonCoreAdvisory(), "tools.jackson.core:jackson-core", "3.1.4");

      // Then: the 2.x branches of com.fasterxml never leak into the card data.
      assertThat(resolution.branches()).hasSize(2);
      assertThat(resolution.branches())
          .extracting(FixedVersionResolver.AffectedWindow::branchLabel)
          .containsExactly("Branch 3.0.x", "Branch 3.2.x");
      assertThat(resolution.fixedVersion()).isEqualTo("3.1.7");
    }

    @Test
    void declaredComFasterxmlIsNotMarkedAsAffected() {
      // Given: the project's declared 2.22.4 sits above the 2.22.3 fix of its own line.
      FixedVersionResolver.Resolution resolution =
          FixedVersionResolver.resolveWithRanges(
              jacksonCoreAdvisory(), "com.fasterxml.jackson.core:jackson-core", "2.22.4");

      // Then: three 2.x branches, none containing the installed version, tools branches absent.
      assertThat(resolution.branches()).hasSize(3);
      assertThat(resolution.branches())
          .allSatisfy(
              branch -> {
                assertThat(branch.containsInstalledVersion()).isFalse();
                assertThat(branch.fixedVersion()).isIn("2.21.7", "2.22.3", "2.18.11");
              });
      assertThat(resolution.fixedVersion()).isEqualTo("2.21.7, 2.22.3, 2.18.11");
    }

    @Test
    void reIntroductionReopensAnUnfixedWindow() {
      // Given: fixed at 1.0.4, re-introduced at 1.0.5 with no fixed event after it.
      OsvVulnerability.Affected affected =
          VulnFixtures.affectedWithWindows(
              "g:a",
              List.of(
                  VulnFixtures.range(
                      "ECOSYSTEM",
                      List.of(
                          VulnFixtures.event("1.0.0", "1.0.4", null, null),
                          VulnFixtures.event("1.0.5", null, null, null)))));
      OsvVulnerability vuln =
          VulnFixtures.vuln("GHSA-2", "s", null, null, List.of(affected), null, null);

      // When
      FixedVersionResolver.Resolution resolution =
          FixedVersionResolver.resolveWithRanges(vuln, "g:a", "1.0.6");

      // Then: the second window is open, has no fix, and contains the installed version.
      assertThat(resolution.branches()).hasSize(2);
      FixedVersionResolver.AffectedWindow second = resolution.branches().get(1);
      assertThat(second.rangeText()).isEqualTo(">=1.0.5");
      assertThat(second.fixedVersion()).isNull();
      assertThat(second.containsInstalledVersion()).isTrue();
      assertThat(resolution.fixedVersion()).isEqualTo("1.0.4");
    }

    @ParameterizedTest(name = "installed {0} is contained: {1}")
    @CsvSource({"2.3.0, true", "2.3.1, true", "2.3.2, false"})
    void lastAffectedClosesInclusively(String installed, boolean expected) {
      // Given
      OsvVulnerability.Affected affected =
          VulnFixtures.affectedWithWindows(
              "g:a",
              List.of(
                  VulnFixtures.range(
                      "ECOSYSTEM", List.of(VulnFixtures.event("2.3.0", null, "2.3.1", null)))));
      OsvVulnerability vuln =
          VulnFixtures.vuln("GHSA-3", "s", null, null, List.of(affected), null, null);

      // When / Then
      assertThat(
              FixedVersionResolver.resolveWithRanges(vuln, "g:a", installed)
                  .branches()
                  .getFirst()
                  .containsInstalledVersion())
          .isEqualTo(expected);
    }

    @Test
    void limitClosesApproximatelyAndNeverProvidesAFix() {
      // Given
      OsvVulnerability.Affected affected =
          VulnFixtures.affectedWithWindows(
              "g:a",
              List.of(
                  VulnFixtures.range(
                      "ECOSYSTEM", List.of(VulnFixtures.event("1.0.0", null, null, "3.0.0")))));
      OsvVulnerability vuln =
          VulnFixtures.vuln("GHSA-4", "s", null, null, List.of(affected), null, null);

      // When
      FixedVersionResolver.Resolution resolution =
          FixedVersionResolver.resolveWithRanges(vuln, "g:a", "1.5.0");

      // Then
      FixedVersionResolver.AffectedWindow branch = resolution.branches().getFirst();
      assertThat(branch.rangeText()).isEqualTo(">=1.0.0, <3.0.0 (approx.)");
      assertThat(branch.fixedVersion()).isNull();
      assertThat(branch.containsInstalledVersion()).isTrue();
      assertThat(FixedVersionResolver.fixedVersions(vuln, "g:a")).isEmpty();
      assertThat(resolution.fixedVersion()).isEqualTo(FixedVersionResolver.UNKNOWN);
    }

    @ParameterizedTest(name = "{0} ranges produce windows")
    @CsvSource({"ECOSYSTEM, true", "SEMVER, true", "GIT, false"})
    void onlyActionableRangeTypesProduceWindows(String type, boolean expected) {
      // Given
      OsvVulnerability.Affected affected =
          VulnFixtures.affectedWithWindows(
              "g:a",
              List.of(
                  VulnFixtures.range(
                      type, List.of(VulnFixtures.event("1.0.0", "1.2.0", null, null)))));
      OsvVulnerability vuln =
          VulnFixtures.vuln("GHSA-5", "s", null, null, List.of(affected), null, null);

      // When / Then
      assertThat(FixedVersionResolver.resolveWithRanges(vuln, "g:a", "1.1.0").branches())
          .hasSize(expected ? 1 : 0);
    }

    @ParameterizedTest(name = "installed [{0}] marks no branch and joins all fixes")
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void blankInstalledVersionJoinsAllFixes(String installed) {
      // Given: two entries for the package.
      OsvVulnerability vuln =
          VulnFixtures.vuln(
              "GHSA-6",
              "s",
              null,
              null,
              List.of(VulnFixtures.affected("g:a", "1.1.0"), VulnFixtures.affected("g:a", "2.5.0")),
              null,
              null);

      // When
      FixedVersionResolver.Resolution resolution =
          FixedVersionResolver.resolveWithRanges(vuln, "g:a", installed);

      // Then: no branch can claim the unknown version but nothing is blank.
      assertThat(resolution.branches()).hasSize(2);
      assertThat(resolution.branches())
          .allSatisfy(b -> assertThat(b.containsInstalledVersion()).isFalse());
      assertThat(resolution.fixedVersion()).isEqualTo("1.1.0, 2.5.0");
    }

    @Test
    void duplicateWindowsAcrossRangeTypesAreDeduplicated() {
      // Given: the same window declared in both ECOSYSTEM and SEMVER ranges.
      OsvVulnerability.Affected affected =
          VulnFixtures.affectedWithWindows(
              "g:a",
              List.of(
                  VulnFixtures.range(
                      "ECOSYSTEM", List.of(VulnFixtures.event("1.0.0", "1.2.0", null, null))),
                  VulnFixtures.range(
                      "SEMVER", List.of(VulnFixtures.event("1.0.0", "1.2.0", null, null)))));
      OsvVulnerability vuln =
          VulnFixtures.vuln("GHSA-7", "s", null, null, List.of(affected), null, null);

      // When / Then
      assertThat(FixedVersionResolver.resolveWithRanges(vuln, "g:a", "1.1.0").branches())
          .hasSize(1);
    }

    @Test
    void sameArtifactSuffixInAnotherGroupIsNotMatched() {
      // Given: the record only affects org.evil:jackson-core.
      OsvVulnerability vuln =
          VulnFixtures.vuln(
              "GHSA-8",
              "s",
              null,
              null,
              List.of(VulnFixtures.affected("org.evil:jackson-core", "1.0.0")),
              null,
              null);

      // When / Then: the com.fasterxml scan must inherit no windows from it.
      FixedVersionResolver.Resolution resolution =
          FixedVersionResolver.resolveWithRanges(
              vuln, "com.fasterxml.jackson.core:jackson-core", "2.20.0");
      assertThat(resolution.branches()).isEmpty();
      assertThat(resolution.fixedVersion()).isEqualTo(FixedVersionResolver.UNKNOWN);
    }

    @Test
    void missingVulnerabilityOrAffectedDataFallsBackToUnknown() {
      // Given / Then
      assertThat(FixedVersionResolver.resolve(null, "g:a", "1.0.0"))
          .isEqualTo(FixedVersionResolver.UNKNOWN);
      assertThat(FixedVersionResolver.resolveWithRanges(null, "g:a", "1.0.0").branches()).isEmpty();
      assertThat(FixedVersionResolver.affectedRanges(null, "g:a")).isEmpty();
      assertThat(FixedVersionResolver.fixedVersions(null, "g:a")).isEmpty();
    }
  }

  @Nested
  @DisplayName("recommendUpgrade")
  class RecommendUpgrade {

    @Test
    void staysWithinTheInstalledBranchEvenWhenAnotherBranchFixesHigher() {
      // Given: advisory A fixes the installed branch; advisory B only fixes 4.0.3.
      OsvVulnerability installedBranch =
          VulnFixtures.vuln(
              "GHSA-A",
              "s",
              null,
              null,
              List.of(
                  VulnFixtures.affectedWithWindows(
                      "tools.jackson.core:jackson-core",
                      List.of(
                          VulnFixtures.range(
                              "ECOSYSTEM",
                              List.of(VulnFixtures.event("3.0.0", "3.1.7", null, null)))))),
              null,
              null);
      OsvVulnerability otherBranch =
          VulnFixtures.vuln(
              "GHSA-B",
              "s",
              null,
              null,
              List.of(
                  VulnFixtures.affectedWithWindows(
                      "tools.jackson.core:jackson-core",
                      List.of(
                          VulnFixtures.range(
                              "ECOSYSTEM",
                              List.of(VulnFixtures.event("4.0.0", "4.0.3", null, null)))))),
              null,
              null);

      // When
      Optional<String> upgrade =
          FixedVersionResolver.recommendUpgrade(
              List.of(installedBranch, otherBranch), "tools.jackson.core:jackson-core", "3.1.4");

      // Then: the recommendation never crosses a branch just because it is higher.
      assertThat(upgrade).contains("3.1.7");
    }

    @Test
    void escalatesToTheHighestFixWhenNoBranchOfTheInstalledVersionIsFixed() {
      // Given: the only fix exists in the next major line.
      OsvVulnerability otherBranch =
          VulnFixtures.vuln(
              "GHSA-B",
              "s",
              null,
              null,
              List.of(
                  VulnFixtures.affectedWithWindows(
                      "g:a",
                      List.of(
                          VulnFixtures.range(
                              "ECOSYSTEM",
                              List.of(VulnFixtures.event("4.0.0", "4.0.3", null, null)))))),
              null,
              null);

      // When
      Optional<String> upgrade =
          FixedVersionResolver.recommendUpgrade(List.of(otherBranch), "g:a", "1.0.0");

      // Then
      assertThat(upgrade).contains("4.0.3");
    }
  }
}
