Transforms unstructured text logs into structured JSON/CSV data and generates reusable SIEM parsing rules (Regex/Grok/KQL).

## Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Features

| Feature | Description |
|---|---|
| **Intelligent Ingestion** | Streams large `.txt` files in chunks to avoid memory overflow |
| **Log Fingerprinting** | Drain-style clustering groups similar logs — only 2–3 samples per pattern are sent to the AI |
| **AI Parsing (Claude)** | Extracts fields, normalizes timestamps to ISO-8601, generates PCRE regex |
| **SIEM Compatibility** | Toggle between Splunk (Regex), Elastic (Grok), or Sentinel (KQL) output |
| **Anonymization Mode** | Masks IPs, emails, and usernames before the AI sees them |
| **Batch Export** | Merge multiple files into one Master CSV, Regex Manifest, or full JSON |

## How It Works

1. **Upload** one or more `.txt` / `.log` / `.csv` files.
2. The app **clusters** log lines by structural similarity (fingerprinting).
3. Representative samples from each cluster are sent to **Claude** for semantic extraction & regex generation.
4. Results are displayed in a **Raw vs. Parsed** side-by-side view.
5. **Export** as Master CSV, Regex Manifest (JSON), or Full Parsed JSON.

## Configuration (Sidebar)

- **Anthropic API Key** — Required. Uses `claude-sonnet-4-20250514`.
- **SIEM Output Format** — Splunk Regex (default), Elastic Grok, or Sentinel KQL.
- **Anonymization Mode** — Toggle to mask PII before AI processing.
- **Samples per cluster** — Number of representative lines sent to the AI per pattern (1–5).

## Sample Log Lines for Testing

```
Mar  5 14:23:01 webserver01 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
2024-03-05T14:23:02.000Z CEF:0|SecurityVendor|Product|1.0|100|Connection blocked|5|src=10.0.0.1 dst=10.0.0.2 spt=1234 dpt=443
<14>1 2024-03-05T14:23:03Z firewall01 snort 9876 - [alert] ET SCAN Potential SSH Scan from 172.16.0.50
```
