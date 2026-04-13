/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.projectsapo.model;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class OsvModelTest {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void testOsvPackage() {
    OsvPackage pkg = new OsvPackage("name", "ecosystem", "version");
    assertEquals("name", pkg.name());
    assertEquals("ecosystem", pkg.ecosystem());
    assertEquals("version", pkg.version());
    assertTrue(pkg.dependencyChains().isEmpty());

    OsvPackage pkgWithChain =
        new OsvPackage("name", "ecosystem", "version", Set.of(List.of("parent", "name")));
    assertEquals(1, pkgWithChain.dependencyChains().size());
    assertTrue(pkgWithChain.dependencyChains().contains(List.of("parent", "name")));
  }

  @Test
  void testOsvQuerySerialization() throws JsonProcessingException {
    OsvPackage pkg = new OsvPackage("pkg", "Maven", "1.0.0");
    OsvQuery query = new OsvQuery("1.0.0", pkg);

    String json = objectMapper.writeValueAsString(query);
    assertTrue(json.contains("\"version\":\"1.0.0\""));
    assertTrue(json.contains("\"package\":{\"name\":\"pkg\",\"ecosystem\":\"Maven\"}"));
  }

  @Test
  void testOsvVulnerabilityDeserialization() throws JsonProcessingException {
    String json =
        """
            {
              "id": "GHSA-123",
              "summary": "Summary",
              "details": "Details",
              "severity": [
                {
                  "type": "CVSS_V3",
                  "score": "9.8"
                }
              ],
              "affected": [
                {
                  "ranges": [
                    {
                      "type": "ECOSYSTEM",
                      "events": [
                        {
                          "introduced": "0",
                          "fixed": "1.0.1"
                        }
                      ]
                    }
                  ]
                }
              ]
            }
            """;

    OsvVulnerability vuln = objectMapper.readValue(json, OsvVulnerability.class);
    assertEquals("GHSA-123", vuln.id());
    assertEquals("Summary", vuln.summary());
    assertEquals("Details", vuln.details());
    assertEquals(1, vuln.severity().size());
    assertEquals("CVSS_V3", vuln.severity().get(0).type());
    assertEquals("9.8", vuln.severity().get(0).score());
    assertEquals(1, vuln.affected().size());
    assertEquals("1.0.1", vuln.affected().get(0).ranges().get(0).events().get(0).fixed());
  }

  @Test
  void testOsvResponseDeserialization() throws JsonProcessingException {
    String json =
        """
            {
              "vulns": [
                {
                  "id": "GHSA-123"
                }
              ]
            }
            """;
    OsvResponse response = objectMapper.readValue(json, OsvResponse.class);
    assertNotNull(response.vulns());
    assertEquals(1, response.vulns().size());
    assertEquals("GHSA-123", response.vulns().get(0).id());
  }
}
