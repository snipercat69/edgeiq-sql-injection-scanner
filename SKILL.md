# SQL Injection Scanner

**Skill Name:** `sql-injection-scanner`  
**Version:** `1.0.0`  
**Category:** Security / Vulnerability Assessment  
**Price:** **Lifetime: $39** / Optional Monthly: $7/mo (includes all Pro features permanently)  
**Author:** EdgeIQ Labs  
**OpenClaw Compatible:** Yes — Python 3, pure stdlib + urllib, WSL + Linux

---

## What It Does

Detects SQL injection vulnerabilities in web application parameters using multiple detection techniques: boolean-based blind injection, time-based blind injection, and UNION SELECT extraction. Designed for security professionals and developers auditing their own applications.

> ⚠️ **Legal Notice:** Only scan domains you own or have explicit written authorization to test. Unauthorized scanning is illegal.

---

## Features

- **Boolean-based blind injection** — infer SQL truth from page response differences
- **Time-based blind injection** — use `SLEEP()` delays to confirm injection
- **UNION SELECT extraction** — pull database version, user, and schema via UNION payloads
- **Auto-detection** — automatically identifies which parameter types are injectable
- **Parameter scanner** — test multiple parameters in a single run
- **JSON export** — structured results for reporting and integration

---

## Tier Comparison

| Feature | Free | **Lifetime ($39)** | Optional Monthly ($7/mo) |
|---------|------|----------------|----------------------|
| Single URL + parameter test | ✅ | ✅ | ✅ |
| Boolean blind detection | ✅ | ✅ | ✅ |
| Time-based detection | ✅ | ✅ | ✅ |
| UNION SELECT extraction | ✅ | ✅ | ✅ |
| Multiple parameter scan | ✅ (unlimited) | ✅ (unlimited) | ✅ (unlimited) |
| JSON export | ✅ | ✅ | ✅ |
| Custom payload wordlist | ✅ | ✅ | ✅ |

---

## Installation

```bash
cp -r /home/guy/.openclaw/workspace/apps/sql-injection-scanner ~/.openclaw/skills/sql-injection-scanner
```

---

## Usage

### Basic scan (free tier)

```bash
python3 sql_scanner.py --url "https://example.com/product?id=1"
```

### Pro scan (time-based + UNION + multiple params)

```bash
EDGEIQ_EMAIL=your_email@gmail.com python3 sql_scanner.py \
  --url "https://example.com/product?id=1&category=2&search=test" \
  --pro
```

### Test specific parameter only

```bash
python3 sql_scanner.py --url "https://example.com/search?q=test" --param q
```

### Full bundle scan with JSON export

```bash
EDGEIQ_EMAIL=your_email@gmail.com python3 sql_scanner.py \
  --url "https://example.com/api/user?id=1" \
  --bundle --output report.json
```

### As OpenClaw Discord Command

In `#edgeiq-support` channel:
```
!sqli https://example.com/product?id=1
!sqli https://example.com/search?q=test --pro
!sqli https://example.com/api?id=1&uid=2 --bundle
```

---

## Parameters

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--url` | string | — | Target URL with parameter(s) |
| `--param` | string | all | Specific parameter to test |
| `--pro` | flag | False | Enable Pro features |
| `--bundle` | flag | False | Enable Bundle features |
| `--output` | string | — | Write JSON report to file |
| `--delay` | float | 1.0 | Delay between requests (seconds) |
| `--timeout` | int | 10 | Request timeout (seconds) |

---

## Output Example

```
=== SQL Injection Scanner ===
Target: https://example.com/product?id=1

  [1mParameter: id — INJECTABLE 🔴[0m
    Method:     Boolean Blind
    Payload:    ' OR 1=1 --
    True resp:  1423 bytes / 200 OK
    False resp: 0 bytes / 302 redirect
    Confidence: HIGH

  [1mParameter: category — SAFE ✅[0m
    Method:     All checks passed
    Response:   1244 bytes / 200 OK

  Database: MySQL 8.0.23 (via UNION)
  User:     app_user@localhost

  Threat Level: CRITICAL — 1 injectable parameter found
```

---

## Pro Upgrade

Boolean blind + time-based + UNION SELECT + multiple parameters:

👉 [Buy Lifetime — $39](https://buy.stripe.com/fZu5kF51NgRL07G2cg7wA10)
👉 [Subscribe Monthly — $7/mo](https://buy.stripe.com/00wfZj2TF1WR7A82cg7wA1d)

---

## Support

Open a ticket in [#edgeiq-support](https://discord.gg/PaP7nsFUJT) or email [gpalmieri21@gmail.com](mailto:gpalmieri21@gmail.com)

---

## 🔗 More from EdgeIQ Labs

**edgeiqlabs.com** — Security tools, OSINT utilities, and micro-SaaS products for developers and security professionals.

- 🛠️ **Subdomain Hunter** — Passive subdomain enumeration via Certificate Transparency
- 📸 **Screenshot API** — URL-to-screenshot API for developers
- 🔔 **uptime.check** — URL uptime monitoring with alerts
- 🛡️ **headers.check** — HTTP security headers analyzer

👉 [Visit edgeiqlabs.com →](https://edgeiqlabs.com)
