# VulnSpotter

**VulnSpotter** is a dependency vulnerability scanner for **IntelliJ IDEA**, powered by the [OSV.dev](https://osv.dev)
database. It scans your project's Gradle and Maven dependencies, flags known vulnerabilities in a dedicated tool window
and directly in the editor, and gives you actionable details — severity, fixed versions, and official advisories —
without leaving the IDE.

## 🚀 Features

- **Gradle & Maven scanning** — Detects declared dependencies in Gradle and Maven projects and checks them against
  OSV.dev (`querybatch` + per-vulnerability hydration, with caching, retries and pagination). Manifest parsers also
  cover `package.json`/`package-lock.json`, `requirements.txt`, and `go.mod` for polyglot repositories. Maven walks
  IntelliJ's resolved dependency tree, pruning dependency paths that lost conflict/duplicate mediation — a common
  outcome in multi-module projects, e.g. when a parent POM manages the version — so only classpath versions are
  reported. Gradle reads the external-system model, whose library versions are already conflict-resolved by Gradle
  before import (libraries from every configuration are included).
- **In-editor highlighting & quick fix** — Vulnerable dependencies are annotated in `pom.xml` and `build.gradle`
  with the vulnerability count, the highest severity and the recommended version. A one-click intention (*Update …
  to …*) upgrades the declaration — including Maven `${property}`-based versions — and refuses to downgrade.
- **Dedicated tool window** — Review all scan results in the *VulnSpotter* tool window, with severity-sorted results,
  filters, search by package or CVE, a context menu (open in OSV.dev, copy coordinate, copy fix version, copy
  upgrade snippet, ignore dependency), and a `mvn dependency:tree`-style path view in the details panel where the
  scanned dependency is highlighted.
- **Accurate severity** — CVSS v2/v3/v3.1/v4 vectors from OSV are actually parsed and scored (via
  `us.springett:cvss-calculator`); `database_specific` labels are only a fallback. Vulnerabilities without severity data
  are shown as **Unknown**, never hidden.
- **Fixed versions** — Remediation versions computed from OSV `ECOSYSTEM`/`SEMVER` ranges with Maven-style version
  semantics (`5.3.9.RELEASE` == `5.3.9`, `2.0.0-RC1` < `2.0.0`), preferring stable releases in the same branch: each
  affected version branch is listed with its own fix and the branch containing the installed version is marked, so
  multi-branch advisories (e.g. a fixed release on both maintenance and current lines) never read as one collapsed range.
- **Dependency provenance** — Each finding states whether the dependency is declared in the project or pulled in
  transitively (and through which root, with its resolved version), so test-framework or build-tool transitives are
  never confused with what the manifest declares. Classpath entries the build never declares — what the
  `intellijPlatform` toolchain places there (provided scope, bundled libraries, its own testing source sets) — are
  reported as *Provided by the intellijPlatform toolchain*, with an `intellijPlatform (provided)` root in the path
  views instead of a misleading "declared" label.
- **Transitive remediation** — For transitive findings the tool window and every export state where the fix belongs: the
  parent dependency's current version plus, deduced from Maven Central metadata (parent/BOM POMs cached locally,
  best-effort), the first released parent version that already ships the vulnerable package at or above its fix
  (e.g. *upgrade spring-boot-starter-web to 4.1.0, which ships jackson-databind 2.17.1*). No network, chain data or
  deducible upgrade simply keeps the generic "upgrade the root" advice; exports expose the findings as
  `parentVersions` / `parentRemediations` (JSON, SARIF), a `Parent Fix` column (CSV) and `Transitive fix` lines (Markdown).
- **Report export** — Export scan results to **HTML**, **PDF**, **CSV**, **JSON**, **SARIF 2.1.0** and **Markdown**
  from the tool window, each finding carrying its `mvn dependency:tree`-style path (the PDF draws ASCII connectors so
  the base-14 fonts can render it); CSV adds a `Dependency Paths` column and JSON/SARIF expose the raw
  `dependencyChains` arrays.
- **Notifications** — Instant IDE notifications about security findings and scan failures.
- **Automatic analysis on project open** — Scans the project's dependencies when it opens and raises an IDE notification
  if pending critical CVEs are found. Opt-in and **disabled by default**.
- **Auto-scan after project sync** — Re-scans after every Gradle or Maven sync. Toggle is **enabled by default**.
- **Settings page** — **Settings → Tools → VulnSpotter**: auto-scan, cache duration, disable vulnerability caching
  (every scan queries OSV.dev), minimum severity shown and ignored CVE/GHSA ids.
- **Exclusions** — Ignore specific dependencies via a `.vulnspotterignore` file in the project root (glob patterns
  supported) or ignore individual CVEs from the Settings page.

## 📋 Requirements

| Requirement     | Version                                     |
|-----------------|---------------------------------------------|
| IntelliJ IDEA   | 2026.3+ (since-build `263`, no upper bound) |
| Java            | 25                                          |
| Bundled plugins | Maven, Gradle, Groovy                       |

## 🛠 Installation

1. Open **Settings/Preferences → Plugins → Marketplace**.
2. Search for **"VulnSpotter"**.
3. Click **Install** and restart the IDE.

Alternatively, install from disk: build the plugin (see [Build](#-build)) and use **Settings → Plugins → ⚙️ → Install
Plugin from Disk...** with the generated ZIP.

## 📖 Usage

1. Open your Gradle or Maven project in IntelliJ IDEA.
2. Open the **VulnSpotter** tool window and run a scan (or enable auto-scan after project sync in **Settings → Tools →
   VulnSpotter**).
3. Review the dependency list — vulnerable packages are highlighted and sorted by severity. Use the filters and the
   search field (package name or CVE id) to focus on what matters.
4. Select a dependency to see its vulnerabilities: severity, CVSS score, summary, affected ranges, fixed versions, CVE
   aliases, and links to the official advisories.
5. Fix directly from the editor: vulnerable declarations in `pom.xml`/`build.gradle` are underlined — press
   <kbd>Alt</kbd>+<kbd>Enter</kbd> and apply *Update &lt;artifact&gt; to &lt;version&gt;*.
6. Export the results to HTML, PDF, CSV, JSON, SARIF or Markdown if you need to share a report.

### Excluding dependencies

Create a `.vulnspotterignore` file in the project root to exclude dependencies from scans:

```
# One pattern per line. Matches the package name or ecosystem:name.
com.example:legacy-lib
lodash
Maven:com.example:*        # glob patterns are supported
com.mycompany.*
```

Individual vulnerabilities (by CVE/GHSA id, aliases included) can be ignored from **Settings → Tools → VulnSpotter**.

## 🏛 Architecture

The codebase follows a hexagonal-style layered architecture under the base package `com.luisppb16.vulnspotter`:

- **ui/** — IntelliJ integration surface: actions (`action`), editor annotator and quick fix (`annotator`), and the tool
  window (`toolwindow`).
- **application/service** — Use-case orchestration (`VulnerabilityScannerService`, `TransitiveRemediationService`).
- **domain/** — Core model and logic: `model` (OSV records, `PackageKey`, `DependencyProvenance`,
  `DependencyChainTree`, `ParentRemediation`) and `service` (`SeverityAnalyzer`, `VersionUtil`, `FixedVersionResolver`).
- **infrastructure/** — Adapters: `osv` (`OsvClient` and constants), `parser` (`DependencyParser`,
  `VulnSpotterIgnoreParser`), `maven` (`MavenCentralClient` for transitive-remediation metadata, `MavenPom`,
  `MavenPomParser`), `report` (report builder, `RemediationComposer`, `DependencyTreeRenderer`, export services),
  `sync` (Gradle and Maven sync listeners) and `startup` (project-open scan activity).
- **settings/** — Persistent plugin configuration (`VulnSpotterSettings`) and its Settings page
  (`VulnSpotterConfigurable`).
- **util/** — Shared helpers (`HtmlEscaper`, `Json`).

**Stack:** Java 25, IntelliJ Platform Gradle Plugin 2.20.0, Gradle 9.8.2, Jackson, cvss-calculator, OpenHTMLtoPDF.

## 🔨 Build

```bash
./gradlew buildPlugin    # Build the distributable ZIP
./gradlew test           # Run the test suite
./gradlew verifyPlugin   # Run the IntelliJ Plugin Verifier
```

Continuous integration runs on **GitHub Actions**: `ci.yml` builds and tests on every push and pull request, and a
release workflow signs and publishes the plugin to the **JetBrains Marketplace** when a GitHub Release is published.

## 🔐 Privacy & Network Behavior

- VulnSpotter contacts exactly two hosts:
  - `api.osv.dev` — `POST /v1/querybatch` to look up dependencies and `GET /v1/vulns/<id>` to fetch the details of the
    vulnerabilities found.
  - `repo1.maven.org` — `GET` of `maven-metadata.xml` and POM documents used to deduce the parent fix for transitive
    findings (best-effort; the answer degrades to "upgrade the root").
- Data sent: dependency coordinates only (`name`, `ecosystem`, `version`). Project source code is **never** sent. No
  telemetry, no third-party endpoints beyond these two.
- Local caches (IDE system directory): OSV answers live in memory only; Maven Central metadata/POMs under
  `system/vulnspotter/maven-central/` unless **Settings → Tools → VulnSpotter → Disable vulnerability caching** is
  marked, in which case every call goes to the network live and nothing is stored.
- Re-scans run after every Gradle/Maven sync (enabled by default); the project-open scan is opt-in and **disabled by
  default**.

## 📝 Changelog

### 1.0.7

- **Real Gradle dependency chains**: transitive findings read the resolved source-set model of the Gradle sync, so
  dependency trees match the build exactly. Classpath entries no build script declares (what the `intellijPlatform`
  toolchain places there) are labeled **Provided by the intellijPlatform toolchain** with an `intellijPlatform
  (provided)` root in the path views instead of a misleading "declared" label.
- **Reports aligned with the tool window**: exports (HTML, PDF, CSV, JSON, SARIF, Markdown) now carry the same Remediation
  box (direct upgrade, per-root advice with generic fallback, platform note) and the `mvn dependency:tree`-style path per
  finding.
- **Preview refresh on re-scan**: the details panel is cleared on every new scan instead of holding stale content.
- **Settings**: new **Disable vulnerability caching** toggle (every scan queries OSV.dev directly and Maven Central is
  hit live with nothing stored — metadata caches included), auto-scan after sync enabled by default, project-open scan
  opt-in, and a cache-duration spinner that grays out while caching is disabled.
- Robustness: a disposed pipeline no longer crashes the caller mid-scan, and completed scans release their pipeline slot.

### 1.0.6

- **Gradle dependency chains**: the scan preserves the Gradle dependency chains, so transitive findings are labeled
  transitive with their roots instead of declared, and carry the root's resolved version in provenance labels.

### 1.0.2

The intermediate releases (1.0.3–1.0.5) only carried build/packaging changes; their features ship as part of 1.0.6.

- Migrated to **Java 25** and **IntelliJ Platform 2026.2** (since-build `262`). The minimum supported IDE is now
  IntelliJ IDEA 2026.2; users of 2025.1–2026.1 should keep using 1.0.0.
- Refactored to use **sealed types**, **pattern matching for switch**, **record patterns**, **text blocks** and
  **unnamed variables**.
- Removed unused Lombok dependency. Bumped Mockito to 5.23.0 and JUnit Jupiter to 5.14.4 for JDK 25 compatibility.
- Sealed `VersionItem` type replaces the previous `List<Object>` token stream in `VersionUtil` for exhaustive, type-safe
  version comparison.

### 1.0.0

- Initial public release of **VulnSpotter** (complete rename and layered-architecture refactor).
- Gradle & Maven dependency scanning via OSV.dev with full vulnerability hydration.
- In-editor annotations in `pom.xml`/`build.gradle` with a one-click upgrade quick fix.
- Real CVSS v2/v3/v4 scoring and Maven-style fixed-version resolution.
- Dedicated tool window with severity sorting, filters, search, and HTML/PDF/CSV/JSON/SARIF/Markdown exports, each
  finding carrying its full dependency path.
- Settings page (auto-scan, cache, disable vulnerability caching, minimum severity, ignored CVEs) and
  `.vulnspotterignore` support.

## 👤 Author

**Luis Pepe**

- Email: ironkrozz@gmail.com
- GitHub: [https://github.com/luisppb16](https://github.com/luisppb16)

## 📄 License

Copyright © 2026 Luis Paolo Pepe Barra (@LuisPPB16). All rights reserved.
