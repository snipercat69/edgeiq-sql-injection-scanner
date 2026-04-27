# SQL Injection Scanner — CLI Setup

A SQL injection vulnerability scanner for web applications you own or have permission to test.

## Prerequisites

- Python 3.8+

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-sql-injection-scanner.git
cd edgeiq-sql-injection-scanner
```

## Quick Start

```bash
# Free scan (boolean blind only)
python3 sql_scanner.py --url "https://example.com/product?id=1"

# Pro scan (boolean + time-based + UNION extraction)
EDGEIQ_EMAIL=your_email@gmail.com python3 sql_scanner.py \
  --url "https://example.com/product?id=1&category=2" \
  --pro

# Bundle scan with JSON export
EDGEIQ_EMAIL=your_email@gmail.com python3 sql_scanner.py \
  --url "https://example.com/search?q=test" \
  --bundle --output report.json
```

## Features

- Boolean-based blind injection detection
- Time-based blind injection (SLEEP/BENCHMARK)
- UNION SELECT database extraction
- Multiple parameter testing
- JSON export for reporting

## ⚠️ Legal Notice

Only scan web applications you own or have explicit written authorization to test. Unauthorized scanning is illegal.

## Licensing

Free tier: basic boolean blind scan.

Pro ($19/mo) or Bundle ($39/mo): [buy.stripe.com/7sYaEZeCn5934nW8AE7wA01](https://buy.stripe.com/7sYaEZeCn5934nW8AE7wA01)

After purchase, save your license key to `~/.edgeiq/license.key` or set your email:
```bash
export EDGEIQ_EMAIL=your@email.com
```
