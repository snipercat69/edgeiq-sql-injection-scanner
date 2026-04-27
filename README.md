# 💉 EdgeIQ SQL Injection Scanner

**Detect SQL injection vulnerabilities in web application parameters.**

Boolean-based blind injection, time-based blind injection, and UNION SELECT extraction — comprehensive SQL injection testing in pure Python.

[![Project Stage](https://img.shields.io/badge/Stage-Beta-blue)](https://edgeiqlabs.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

---

## What It Does

Detects SQL injection vulnerabilities using multiple detection techniques: boolean-based blind injection (differential response analysis), time-based blind injection (SLEEP delay confirmation), and UNION SELECT extraction (data pull).

> ⚠️ **Legal Notice:** Only scan domains you own or have explicit written authorization to test.

---

## Key Features

- **Boolean-based blind injection** — infer SQL truth from page response differences
- **Time-based blind injection** — SLEEP() delay to confirm injection
- **UNION SELECT extraction** — pull database version, user, schema via UNION
- **Auto-detection** — automatically identifies injectable parameters
- **Parameter scanner** — test multiple parameters in a single run
- **JSON export** — structured results for reporting

---

## Prerequisites

- Python 3.8+
- **Pure stdlib** — no external dependencies

---

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-sql-injection-scanner.git
cd edgeiq-sql-injection-scanner
# No pip install needed!
```

---

## Quick Start

```bash
# Test a single URL parameter
python3 sql_scanner.py --url "https://example.com/product?id=1" --param id

# Auto-detect injectable parameters
python3 sql_scanner.py --url "https://example.com/search?q=test" --scan-all

# Export results
python3 sql_scanner.py --url "https://example.com/item?id=1" --param id --format json --output findings.json
```

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 3 scans/month, basic payloads |
| **Lifetime** | $39 one-time | Unlimited scans, full payload set, custom wordlists |
| **Monthly** | $7/mo | All Lifetime features, billed monthly |

---

## Integration with EdgeIQ Tools

- **[EdgeIQ API Endpoint Discovery](https://github.com/snipercat69/edgeiq-api-endpoint-discovery)** — test discovered API parameters
- **[EdgeIQ Alerting System](https://github.com/snipercat69/edgeiq-alerting-system)** — deliver SQL injection findings

---

## Support

Open an issue at: https://github.com/snipercat69/edgeiq-sql-injection-scanner/issues

---

*Part of EdgeIQ Labs — [edgeiqlabs.com](https://edgeiqlabs.com)*
