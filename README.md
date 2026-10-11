<div align="center">

<img src="docs/screenshots/banner.png" alt="SecAgent" width="100%">

# SecAgent

**A multi-language static security analyzer for developers who care about shipping secure code.**

[![Latest Release](https://img.shields.io/github/v/release/alimoemeni/SecAgent?style=flat-square&color=00D9FF&label=release)](https://github.com/alimoemeni/SecAgent/releases)
[![License](https://img.shields.io/github/license/alimoemeni/SecAgent?style=flat-square&color=green)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?style=flat-square&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2B-0078D4?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

[Download](#-installation) · [Documentation](docs/) · [Report a Bug](https://github.com/alimoemeni/SecAgent/issues/new?template=bug_report.md) · [Request a Feature](https://github.com/alimoemeni/SecAgent/issues/new?template=feature_request.md)

</div>

---

## Why SecAgent?

I spent years watching developers push code they *knew* might have issues — not because they didn't care, but because the existing tools were either too expensive, too complicated to set up, or wanted to upload their source code to someone else's cloud.

SecAgent is my answer to that. It's a **desktop application** that runs entirely on your machine, scans your source code for common security flaws, and — this is the part most tools don't do — **generates fixed versions of your files** so you're not just told about the problem, you get a head start on solving it.

No servers. No accounts. No telemetry. No code leaving your computer. Ever.

---

## What It Does

SecAgent reads your source files, applies a set of security rules, and reports findings with severity, CWE reference, exact file location, and a code snippet. Then, for the vulnerabilities it can handle, it produces a patched copy of the file.

It currently supports **seven languages** and **seven security rules** — carefully chosen to cover the issues that show up most often in real codebases.

<table>
<tr>
<td valign="top" width="50%">

### Supported Languages

- 🟣 **C#** — `.cs`
- 🟡 **Python** — `.py`
- 🟨 **JavaScript** — `.js`, `.mjs`, `.cjs`
- 🔵 **TypeScript** — `.ts`
- 🟪 **PHP** — `.php`, `.phtml`
- 🟠 **HTML** — `.html`, `.htm`
- 🔷 **CSS** — `.css`

</td>
<td valign="top" width="50%">

### Security Rules

| Rule | CWE |
|------|-----|
| SQL Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| Command Injection | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| Cross-Site Scripting | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| Hardcoded Secrets | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| Weak Cryptography | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) |
| Insecure Randomness | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) |
| Empty Catch Blocks | [CWE-390](https://cwe.mitre.org/data/definitions/390.html) |

</td>
</tr>
</table>

---

## Screenshots

<div align="center">

### Dashboard
<img src="dashbaord.PNG" alt="Dashboard" width="800">

### Scanning a project
<img src="scan.PNG" alt="Scan Page" width="800">

### Results with filtering
<img src="results.PNG" alt="Results Page" width="800">

### Auto-Fix — patched files
<img src="autofix.PNG" alt="Auto-Fix Page" width="800">

</div>

> 📸 *Screenshots coming soon. Place them in `docs/screenshots/` to render.*

---

## Installation

### Option 1 — Download the executable (recommended)

1. Head to the [Releases page](https://github.com/alimoemeni/SecAgent/releases)
2. Download the latest `SecAgent-vX.X.X-win-x64.zip`
3. Extract the archive anywhere you like
4. Double-click `SecAgent.exe`

That's it. **No .NET runtime, no installer, no admin rights needed.** The executable bundles everything it needs.

> If Windows SmartScreen warns you about an unknown publisher, click **More info** → **Run anyway**. This happens for any new executable without an expensive code-signing certificate.

