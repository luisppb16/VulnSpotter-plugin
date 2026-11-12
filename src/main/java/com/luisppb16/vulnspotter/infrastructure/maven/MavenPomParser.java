/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.maven;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.jetbrains.annotations.Nullable;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Parses Maven POM and {@code maven-metadata.xml} documents into {@link MavenPom} records. Parsing
 * is total: any malformed, foreign or unexpected document degrades to an empty answer rather than
 * throwing, because the transitive remediation it feeds is best-effort.
 */
public final class MavenPomParser {

  private MavenPomParser() {
    throw new UnsupportedOperationException("Utility class");
  }

  /** The {@code <versioning><versions>} entries of a {@code maven-metadata.xml} document. */
  public static List<String> parseMetadataVersions(String xml) {
    Element root = parseDocument(xml, "metadata");
    if (root == null) {
      return List.of();
    }
    List<String> versions = new ArrayList<>();
    Element versioning = firstChild(root, "versioning").orElse(null);
    Element versionsElement = firstChild(versioning, "versions").orElse(null);
    for (Element versionElement : children(versionsElement, "version")) {
      String version = versionElement.getTextContent();
      if (version != null && !version.isBlank()) {
        versions.add(version.trim());
      }
    }
    return versions;
  }

  /** The {@code <project>} document as a {@link MavenPom}; empty for anything unparseable. */
  public static Optional<MavenPom> parsePom(String xml) {
    Element project = parseDocument(xml, "project");
    if (project == null) {
      return Optional.empty();
    }

    Optional<Element> parentElement = firstChild(project, "parent");
    MavenPom.Coordinate parent = null;
    if (parentElement.isPresent()) {
      String group = childText(parentElement.get(), "groupId");
      String artifact = childText(parentElement.get(), "artifactId");
      String version = childText(parentElement.get(), "version");
      if (group != null && artifact != null && version != null && !version.isBlank()) {
        parent = new MavenPom.Coordinate(group, artifact, version);
      }
    }

    Map<String, String> properties = new LinkedHashMap<>();
    for (Element property : children(firstChild(project, "properties").orElse(null), null)) {
      String value = property.getTextContent();
      if (value != null) {
        properties.put(property.getTagName(), value.trim());
      }
    }

    Element managedDependenciesElement =
        firstChild(project, "dependencyManagement")
            .flatMap(management -> firstChild(management, "dependencies"))
            .orElse(null);
    List<MavenPom.Dependency> managedDependencies = parseDependencies(managedDependenciesElement);
    List<MavenPom.Dependency> dependencies =
        parseDependencies(firstChild(project, "dependencies").orElse(null));

    return Optional.of(new MavenPom(parent, properties, managedDependencies, dependencies));
  }

  private static List<MavenPom.Dependency> parseDependencies(
      @Nullable Element dependenciesElement) {
    if (dependenciesElement == null) {
      return List.of();
    }
    List<MavenPom.Dependency> dependencies = new ArrayList<>();
    for (Element dependencyElement : children(dependenciesElement, "dependency")) {
      MavenPom.Dependency dependency = parseDependency(dependencyElement);
      if (dependency != null) {
        dependencies.add(dependency);
      }
    }
    return dependencies;
  }

  private static MavenPom.Dependency parseDependency(Element dependencyElement) {
    String group = childText(dependencyElement, "groupId");
    String artifact = childText(dependencyElement, "artifactId");
    if (group == null || artifact == null) {
      return null;
    }
    String version = childText(dependencyElement, "version");
    String type = childText(dependencyElement, "type");
    String scope = childText(dependencyElement, "scope");
    String optional = childText(dependencyElement, "optional");
    return new MavenPom.Dependency(group, artifact, version, type, scope, "true".equals(optional));
  }

  /** Root element of the first {@code expectedRootName} document; null on any failure. */
  private static Element parseDocument(String xml, String expectedRootName) {
    if (xml == null || xml.isBlank()) {
      return null;
    }
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      try {
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
      } catch (Exception ignored) {
        // Old parsers may reject the hardening attributes; the documents are still parsed safely.
      }
      Document document =
          factory
              .newDocumentBuilder()
              .parse(new org.xml.sax.InputSource(new java.io.StringReader(xml)));
      Element root = document.getDocumentElement();
      if (root == null || !expectedRootName.equals(root.getTagName())) {
        return null;
      }
      return root;
    } catch (Exception e) {
      return null;
    }
  }

  private static Optional<Element> firstChild(Element parent, String tagName) {
    if (parent == null || tagName == null) {
      return Optional.empty();
    }
    List<Element> candidates = children(parent, tagName);
    return candidates.isEmpty() ? Optional.empty() : Optional.of(candidates.getFirst());
  }

  /** Direct child elements of {@code parent}; tag name {@code null} selects every child. */
  private static List<Element> children(Element parent, String tagName) {
    List<Element> children = new ArrayList<>();
    if (parent == null) {
      return children;
    }
    for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
      if (node instanceof Element child
          && (tagName == null || tagName.equals(child.getTagName()))) {
        children.add(child);
      }
    }
    return children;
  }

  /** Text content of the first direct child element with the given tag name. */
  private static String childText(Element parent, String tagName) {
    Optional<Element> element = firstChild(parent, tagName);
    if (element.isEmpty()) {
      return null;
    }
    String text = element.get().getTextContent();
    return text != null && !text.isBlank() ? text.trim() : null;
  }
}
