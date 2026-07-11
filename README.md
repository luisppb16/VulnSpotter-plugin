# VulnSpotter

**VulnSpotter** is a dependency vulnerability scanner for **IntelliJ IDEA**, powered by the [OSV.dev](https://osv.dev)
database. It scans your project's Gradle and Maven dependencies, flags known vulnerabilities in a dedicated tool
window, and gives you actionable details — severity, fixed versions, and official advisories — without leaving the IDE.

## 🚀 Features

- **Gradle & Maven scanning** — Detects declared dependencies in Gradle and Maven projects and checks them against
  OSV.dev. Fallback parsers cover `package.json`, `requirements.txt`, and `go.mod`.
- **Dedicated tool window** — Review all scan results in the *VulnSpotter* tool window, with filters and search to
  narrow down large dependency lists.
- **Vulnerability details** — Summaries, severity levels (derived from CVSS and `database_specific` data), affected
  ranges, and one-click access to official advisories (CVE, GHSA, etc.).
- **Fixed versions** — Remediation versions extracted from OSV data, with scraping of `osv.dev` vulnerability pages as
  a fallback when the API response lacks them.
- **Report export** — Export scan results to **HTML**, **PDF**, and **CSV** from the tool window (the export service
  also supports **SARIF** and **JSON**).
- **Notifications** — Instant IDE notifications about security findings.
- **Auto-scan after project sync** — Optionally re-scan whenever the project is synced. Opt-in and **disabled by
  default**.
- **Exclusions** — Ignore specific dependencies via a `.vulnspotterignore` file in the project root (one dependency per
  line, `#` for comments).

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
2. Open the **VulnSpotter** tool window and run a scan (or enable auto-scan after project sync in the plugin settings).
3. Review the dependency list — vulnerable packages are highlighted. Use the filters and the search field to focus on
   what matters.
4. Select a dependency to see its vulnerabilities: severity, summary, fixed versions, and links to the official
   advisories.
5. Export the results to HTML, PDF, or CSV if you need to share a report.

### Excluding dependencies

Create a `.vulnspotterignore` file in the project root to exclude dependencies from scans:

```
# One dependency per line
com.example:legacy-lib
lodash
```

## 🏛 Architecture

The codebase follows a hexagonal-style layered architecture under the base package `com.luisppb16.vulnspotter`:

- **ui/** — IntelliJ integration surface: actions (`action`), editor annotator (`annotator`), and the tool window
  (`toolwindow`).
- **application/service** — Use-case orchestration (`VulnerabilityScannerService`).
- **domain/** — Core model and logic: `model` (OSV records and `PackageKey`) and `service` (`SeverityAnalyzer`,
  `VersionUtil`).
- **infrastructure/** — Adapters: `osv` (`OsvClient` and constants), `parser` (`DependencyParser`,
  `VulnSpotterIgnoreParser`), `report` (report builder and export), and `sync` (`ProjectSyncListener`).
- **settings/** — Persistent plugin configuration (`VulnSpotterSettings`).
- **util/** — Shared helpers (`HtmlEscaper`).

**Stack:** Java 21, IntelliJ Platform Gradle Plugin 2.18.1, Gradle 9.6.1, Jackson, OpenHTMLtoPDF, Lombok.

## 🔨 Build

```bash
./gradlew buildPlugin    # Build the distributable ZIP
./gradlew test           # Run the test suite
./gradlew verifyPlugin   # Run the IntelliJ Plugin Verifier
```

Continuous integration runs on **GitHub Actions**: `ci.yml` builds and tests on every push and pull request, and a
release workflow signs and publishes the plugin to the **JetBrains Marketplace** when a GitHub Release is published.

## 🔐 Privacy & Network Behavior

- VulnSpotter calls `api.osv.dev` to check for vulnerabilities.
- Data sent: dependency coordinates only (`name`, `ecosystem`, `version`).
- Project source code is **never** sent.
- The fixed-versions fallback scrapes `osv.dev/vulnerability/<id>` pages for the vulnerabilities already found.
- Automatic scan after project sync is **opt-in** and disabled by default.

## 📝 Changelog

### 1.0.0

- Initial public release of **VulnSpotter** (complete rename and layered-architecture refactor).
- Gradle & Maven dependency scanning via OSV.dev.
- Dedicated tool window with filters, search, and HTML/PDF/CSV exports.
- `.vulnspotterignore` support for excluding dependencies from scans.

## 👤 Author

**Luis Pepe**

- Email: ironkrozz@gmail.com
- GitHub: [https://github.com/luisppb16](https://github.com/luisppb16)

## 📄 License

Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16). All rights reserved.
