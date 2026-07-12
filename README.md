# VulnSpotter

**VulnSpotter** is a dependency vulnerability scanner for **IntelliJ IDEA**, powered by the [OSV.dev](https://osv.dev)
database. It scans your project's Gradle and Maven dependencies, flags known vulnerabilities in a dedicated tool
window and directly in the editor, and gives you actionable details — severity, fixed versions, and official
advisories — without leaving the IDE.

## 🚀 Features

- **Gradle & Maven scanning** — Detects declared dependencies in Gradle and Maven projects and checks them against
  OSV.dev (`querybatch` + per-vulnerability hydration, with caching, retries and pagination). Manifest parsers also
  cover `package.json`/`package-lock.json`, `requirements.txt`, and `go.mod` for polyglot repositories.
- **In-editor highlighting & quick fix** — Vulnerable dependencies are annotated in `pom.xml` and `build.gradle`
  with the vulnerability count, the highest severity and the recommended version. A one-click intention (*Update …
  to …*) upgrades the declaration — including Maven `${property}`-based versions — and refuses to downgrade.
- **Dedicated tool window** — Review all scan results in the *VulnSpotter* tool window, with severity-sorted results,
  filters, search by package or CVE, and a context menu (open in OSV.dev, copy coordinate, copy fix version, copy
  upgrade snippet, ignore dependency).
- **Accurate severity** — CVSS v2/v3/v3.1/v4 vectors from OSV are actually parsed and scored (via
  `us.springett:cvss-calculator`); `database_specific` labels are only a fallback. Vulnerabilities without severity
  data are shown as **Unknown**, never hidden.
- **Fixed versions** — Remediation versions computed from OSV `ECOSYSTEM`/`SEMVER` ranges with Maven-style version
  semantics (`5.3.9.RELEASE` == `5.3.9`, `2.0.0-RC1` < `2.0.0`), preferring stable releases in the same major branch.
- **Report export** — Export scan results to **HTML**, **PDF**, **CSV**, **JSON**, **SARIF 2.1.0** and **Markdown**
  from the tool window.
- **Notifications** — Instant IDE notifications about security findings and scan failures.
- **Auto-scan after project sync** — Optionally re-scan after every Gradle or Maven sync. Opt-in and **disabled by
  default**.
- **Settings page** — **Settings → Tools → VulnSpotter**: auto-scan, cache duration, minimum severity shown, and
  ignored CVE/GHSA ids.
- **Exclusions** — Ignore specific dependencies via a `.vulnspotterignore` file in the project root (glob patterns
  supported) or ignore individual CVEs from the Settings page.

## 📋 Requirements

| Requirement     | Version                                        |
|-----------------|------------------------------------------------|
| IntelliJ IDEA   | 2025.1+ (since-build `251`, no upper bound)      |
| Java            | 21                                             |
| Bundled plugins | Maven, Gradle, Groovy                          |

## 🛠 Installation

1. Open **Settings/Preferences → Plugins → Marketplace**.
2. Search for **"VulnSpotter"**.
3. Click **Install** and restart the IDE.

Alternatively, install from disk: build the plugin (see [Build](#-build)) and use
**Settings → Plugins → ⚙️ → Install Plugin from Disk...** with the generated ZIP.

## 📖 Usage

1. Open your Gradle or Maven project in IntelliJ IDEA.
2. Open the **VulnSpotter** tool window and run a scan (or enable auto-scan after project sync in
   **Settings → Tools → VulnSpotter**).
3. Review the dependency list — vulnerable packages are highlighted and sorted by severity. Use the filters and the
   search field (package name or CVE id) to focus on what matters.
4. Select a dependency to see its vulnerabilities: severity, CVSS score, summary, affected ranges, fixed versions,
   CVE aliases, and links to the official advisories.
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

Individual vulnerabilities (by CVE/GHSA id, aliases included) can be ignored from
**Settings → Tools → VulnSpotter**.

## 🏛 Architecture

The codebase follows a hexagonal-style layered architecture under the base package `com.luisppb16.vulnspotter`:

- **ui/** — IntelliJ integration surface: actions (`action`), editor annotator and quick fix (`annotator`), and the
  tool window (`toolwindow`).
- **application/service** — Use-case orchestration (`VulnerabilityScannerService`).
- **domain/** — Core model and logic: `model` (OSV records and `PackageKey`) and `service` (`SeverityAnalyzer`,
  `VersionUtil`, `FixedVersionResolver`).
- **infrastructure/** — Adapters: `osv` (`OsvClient` and constants), `parser` (`DependencyParser`,
  `VulnSpotterIgnoreParser`), `report` (report builder and export), and `sync` (Gradle and Maven sync listeners).
- **settings/** — Persistent plugin configuration (`VulnSpotterSettings`) and its Settings page
  (`VulnSpotterConfigurable`).
- **util/** — Shared helpers (`HtmlEscaper`).

**Stack:** Java 21, IntelliJ Platform Gradle Plugin 2.18.1, Gradle 9.6.1, Jackson, cvss-calculator, OpenHTMLtoPDF,
Lombok.

## 🔨 Build

```bash
./gradlew buildPlugin    # Build the distributable ZIP
./gradlew test           # Run the test suite
./gradlew verifyPlugin   # Run the IntelliJ Plugin Verifier
```

Continuous integration runs on **GitHub Actions**: `ci.yml` builds and tests on every push and pull request, and a
release workflow signs and publishes the plugin to the **JetBrains Marketplace** when a GitHub Release is published.

## 🔐 Privacy & Network Behavior

- VulnSpotter calls `api.osv.dev` only: `POST /v1/querybatch` to look up dependencies and `GET /v1/vulns/<id>` to
  fetch the details of the vulnerabilities found.
- Data sent: dependency coordinates only (`name`, `ecosystem`, `version`).
- Project source code is **never** sent. No scraping, telemetry or third-party endpoints.
- Automatic scan after project sync is **opt-in** and disabled by default.

## 📝 Changelog

### 1.0.0

- Initial public release of **VulnSpotter** (complete rename and layered-architecture refactor).
- Gradle & Maven dependency scanning via OSV.dev with full vulnerability hydration.
- In-editor annotations in `pom.xml`/`build.gradle` with a one-click upgrade quick fix.
- Real CVSS v2/v3/v4 scoring and Maven-style fixed-version resolution.
- Dedicated tool window with severity sorting, filters, search, and HTML/PDF/CSV/JSON/SARIF/Markdown exports.
- Settings page (auto-scan, cache, minimum severity, ignored CVEs) and `.vulnspotterignore` support.

## 👤 Author

**Luis Pepe**

- Email: ironkrozz@gmail.com
- GitHub: [https://github.com/luisppb16](https://github.com/luisppb16)

## 📄 License

Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16). All rights reserved.
