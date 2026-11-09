/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.luisppb16.vulnspotter.domain.model.DependencyProvenance;
import com.luisppb16.vulnspotter.domain.model.OsvPackage;
import com.luisppb16.vulnspotter.domain.model.ParentRemediation;
import com.luisppb16.vulnspotter.domain.service.FixedVersionResolver;
import com.luisppb16.vulnspotter.infrastructure.maven.MavenCentralClient;
import com.luisppb16.vulnspotter.testsupport.VulnFixtures;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("TransitiveRemediationService Test Suite")
class TransitiveRemediationServiceTest {

  private static final String ROOT = "org.springframework:spring-boot-starter-web";
  private static final String CHILD = "com.fasterxml.jackson.core:jackson-databind";
  private static final String REQUIRED_FIX = "2.17.0";

  @Mock private MavenCentralClient client;

  private TransitiveRemediationService service;

  private static OsvPackage transitiveJackson() {
    return VulnFixtures.pkgWithChains(CHILD, "2.17.0", List.of(List.of(ROOT, CHILD)));
  }

  @BeforeEach
  void setUp() {
    service = new TransitiveRemediationService(client);
  }

  @Test
  @DisplayName("should_return_one_remediation_per_root_with_the_deduced_fixing_parent")
  void shouldReturnOneRemediationPerRootWithTheDeducedFixingParent() {
    // Given: Maven Central deduces the first parent release that ships the fixed child.
    when(client.fixingVersion(
            "org.springframework", "spring-boot-starter-web", "3.2.1", CHILD, REQUIRED_FIX))
        .thenReturn(Optional.of(new MavenCentralClient.FixingVersion("4.1.0", "2.18.0")));

    // When
    List<ParentRemediation> remediations =
        service.resolve(transitiveJackson(), REQUIRED_FIX, Map.of(ROOT, "3.2.1"));

    // Then
    assertThat(remediations)
        .containsExactly(new ParentRemediation(ROOT, "3.2.1", "4.1.0", "2.18.0"));
  }

  @Test
  @DisplayName("should_keep_the_scan_only_answer_when_the_parent_cannot_be_deduced")
  void shouldKeepTheScanOnlyAnswerWhenTheParentCannotBeDeduced() {
    // Given: the best-effort lookup fails for the root.
    when(client.fixingVersion(
            "org.springframework", "spring-boot-starter-web", "3.2.1", CHILD, REQUIRED_FIX))
        .thenReturn(Optional.empty());

    // When
    List<ParentRemediation> remediations =
        service.resolve(transitiveJackson(), REQUIRED_FIX, Map.of(ROOT, "3.2.1"));

    // Then: the fallback remediation still names the root and its current version.
    assertThat(remediations).containsExactly(new ParentRemediation(ROOT, "3.2.1", null, null));
  }

  @Test
  @DisplayName("should_resolve_even_without_a_known_current_parent_version")
  void shouldResolveEvenWithoutAKnownCurrentParentVersion() {
    // Given: the scan index does not know the root's current version.
    when(client.fixingVersion(
            eq("org.springframework"),
            eq("spring-boot-starter-web"),
            isNull(),
            eq(CHILD),
            eq(REQUIRED_FIX)))
        .thenReturn(Optional.of(new MavenCentralClient.FixingVersion("4.1.0", "2.18.0")));

    // When
    List<ParentRemediation> remediations =
        service.resolve(transitiveJackson(), REQUIRED_FIX, Map.of());

    // Then
    assertThat(remediations).containsExactly(new ParentRemediation(ROOT, null, "4.1.0", "2.18.0"));
  }

  @Test
  @DisplayName("should_skip_resolution_when_no_fix_is_required")
  void shouldSkipResolutionWhenNoFixIsRequired() {
    // Given / When: a null and an unknown required fix.
    List<ParentRemediation> withNull =
        service.resolve(transitiveJackson(), null, Map.of(ROOT, "3.2.1"));
    List<ParentRemediation> withUnknown =
        service.resolve(transitiveJackson(), FixedVersionResolver.UNKNOWN, Map.of(ROOT, "3.2.1"));

    // Then: no parent lookup ever happens.
    assertThat(withNull).isEmpty();
    assertThat(withUnknown).isEmpty();
    verify(client, never()).fixingVersion(anyString(), anyString(), any(), any(), any());
  }

  @Test
  @DisplayName("should_skip_resolution_for_packages_without_dependency_chains")
  void shouldSkipResolutionForPackagesWithoutDependencyChains() {
    // Given: a package whose scan never learned how it reached the project.
    OsvPackage plain = VulnFixtures.pkg("g:a", "1.0.0");

    // When / Then
    assertThat(service.resolve(plain, REQUIRED_FIX, Map.of(plain.name(), "1.0.0"))).isEmpty();
    assertThat(service.resolve(null, REQUIRED_FIX, Map.of())).isEmpty();
  }

  @Test
  @DisplayName("should_skip_platform_roots_and_their_parent_lookup")
  void shouldSkipPlatformRootsAndTheirParentLookup() {
    // Given: a package whose only chain the IDE platform toolchain injected.
    OsvPackage platformOnly =
        VulnFixtures.pkgWithChains(
            CHILD, "2.17.0", List.of(List.of(DependencyProvenance.PLATFORM_ROOT, CHILD)));

    // When
    List<ParentRemediation> remediations = service.resolve(platformOnly, REQUIRED_FIX, Map.of());

    // Then: no Maven Central lookup, no platform suggestion.
    assertThat(remediations).isEmpty();
    verify(client, never()).fixingVersion(anyString(), anyString(), any(), any(), any());
  }

  @Test
  @DisplayName("should_only_resolve_the_real_root_when_a_platform_chain_is_also_present")
  void shouldOnlyResolveTheRealRootWhenAPlatformChainIsAlsoPresent() {
    // Given: Maven Central deduces the fix for the real root only.
    when(client.fixingVersion(
            "org.springframework", "spring-boot-starter-web", "3.2.1", CHILD, REQUIRED_FIX))
        .thenReturn(Optional.of(new MavenCentralClient.FixingVersion("4.1.0", "2.18.0")));
    OsvPackage mixed =
        VulnFixtures.pkgWithChains(
            CHILD,
            "2.17.0",
            List.of(List.of(ROOT, CHILD), List.of(DependencyProvenance.PLATFORM_ROOT, CHILD)));

    // When
    List<ParentRemediation> remediations =
        service.resolve(mixed, REQUIRED_FIX, Map.of(ROOT, "3.2.1"));

    // Then
    assertThat(remediations)
        .containsExactly(new ParentRemediation(ROOT, "3.2.1", "4.1.0", "2.18.0"));
  }
}
