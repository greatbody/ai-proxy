# AI Proxy (LLM Traffic Capture + Local Web UI)

[![Star History Chart](https://api.star-history.com/svg?repos=greatbody/ai-proxy&type=Date)](https://star-history.com/#greatbody/ai-proxy&Date)

This project provides an HTTPS interception proxy for debugging what your AI agent sends to LLM providers.

By default, it captures all traffic passing through the proxy. You can optionally restrict recording to specific domains via the `CAPTURE_DOMAINS` configuration.

## Features

- Capture request data: method, URL, headers, body
- Capture response data (optional): status, headers, body
- Domain allowlist filtering (`CAPTURE_DOMAINS`, set to `*` for all traffic)
- OpenAI/OpenAI-compatible metadata extraction
  - `provider` (e.g. `openai`, `openai_compatible`)
  - `session_id` heuristics (labels, metadata, or fingerprinting)
  - **Automated session fingerprinting** based on initial message content (prevents grouping everything under `none`).
  - `model` and `input_chars_estimate`
- Provider/session extraction for:
  - `openai` / `openai_compatible`
  - `azure_openai`
  - `anthropic`
  - `gemini`
- Local Web UI (no auth) for:
  - browsing flows
  - grouping by timeline bucket and session
  - collapsible timeline -> session -> flow correlation
  - viewing parsed request/response JSON side-by-side
  - exporting selected session/time window to JSON or CSV

## Files

- `llm_capture_addon.py`: mitmproxy addon (capture + metadata)
- `run_proxy.sh`: starts proxy at `127.0.0.1:8080` (foreground)
- `run_proxy.bat`: Windows proxy launcher
- `webui.py`: local API + UI server
- `run_webui.sh`: starts web UI server (foreground)
- `run_webui.bat`: Windows web UI launcher
- `webui/static/index.html`: frontend
- `inspect_logs.py`: CLI analyzer for largest requests
- `.env.example`: runtime config

## Quick Start

1. Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Configure:

```bash
cp .env.example .env
```

### Option A: Manual Setup (Foreground)

#### macOS/Linux:
1. Start proxy:
```bash
./run_proxy.sh
```

2. Start web UI:
```bash
./run_webui.sh
```

#### Windows:
1. Start proxy:
```cmd
run_proxy.bat
```

2. Start web UI:
```cmd
run_webui.bat
```


### Option B: macOS Background Services

1. Ensure you have configured the background service scripts in the `scripts/` directory (see [macOS Configuration](#macos-configuration) below).

2. Install and start services:
```bash
./scripts/install-services.sh
```

3. Check status:
```text
http://127.0.0.1:8765
```

## Usage

1. **Point your agent/process to the proxy**:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

## Important: Trust mitmproxy CA Certificate

To inspect HTTPS bodies, your client must trust mitmproxy's local CA cert.

After first proxy run, cert files are created under `~/.mitmproxy/`.

- macOS: import `~/.mitmproxy/mitmproxy-ca-cert.pem` into System keychain and set to Always Trust.
- Windows: import `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.pem` into Trusted Root Certification Authorities.
- Python requests/curl: optionally set `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` to this cert.

Without trust setup, HTTPS clients may fail TLS verification.

## Config (`.env`)

- `CAPTURE_DOMAINS`: comma-separated allowlist, supports exact and subdomains. Set to `*` (default) to capture everything.
- `LOG_DIR`: output root (default `logs`)
- `SAVE_RESPONSES`: `true` or `false`
- `REDACT_AUTH`: redact `Authorization` header (`true` recommended)
- `MAX_BODY_BYTES`: body byte cap persisted per record
- `WEBUI_HOST`: web UI host (default `127.0.0.1`)
- `WEBUI_PORT`: web UI port (default `8765`)

## Data Layout

- `logs/requests/<flow_id>.json`
- `logs/responses/<flow_id>.json`
- `logs/events.ndjson`

## CLI Analysis (Optional)

```bash
./inspect_logs.py --log-dir logs --top 20
```

## Notes and Limits

- UI has no password by design and is for local-only usage.
- Session grouping is heuristic for OpenAI-compatible payloads; if no session id exists, entries appear under `none`.
- Captured logs may include sensitive data; protect local files accordingly.

## Web UI API

- `GET /api/flows?provider=...&session_id=...&from=...&to=...&limit=...`
- `GET /api/flows/<flow_id>`
- `GET /api/sessions?provider=...&from=...&to=...`
- `GET /api/timeline_sessions?provider=...&session_id=...&from=...&to=...`
- `GET /api/export?format=json|csv&provider=...&session_id=...&from=...&to=...`

## macOS Configuration

The macOS background service scripts are located in the `scripts/` directory. Since they contain absolute paths specific to your user profile, they are ignored by Git.

To configure them for your system:

1. **Create the directory**: `mkdir -p scripts`
2. **Copy the following templates** into the `scripts/` directory, replacing `/path/to/ai-proxy` with your actual project root path.

### 1. `scripts/run_proxy_service.sh`
```bash
#!/usr/bin/env bash
set -euo pipefail
# Replace with your project path
source /PATH/TO/PROJECT/.venv/bin/activate
exec /PATH/TO/PROJECT/run_proxy.sh
```

### 2. `scripts/run_webui_service.sh`
```bash
#!/usr/bin/env bash
set -euo pipefail
# Replace with your project path
source /PATH/TO/PROJECT/.venv/bin/activate
exec /PATH/TO/PROJECT/run_webui.sh
```

### 3. `scripts/ai.proxy.mitm.plist`
Download/create this plist and replace all absolute paths.

### 4. `scripts/ai.proxy.webui.plist`
Download/create this plist and replace all absolute paths.

### 5. `scripts/install-services.sh`
This script copies the `.plist` files to `~/Library/LaunchAgents/` and loads them via `launchctl`.

---

> **Note**: After creating these files, remember to make the `.sh` files executable: `chmod +x scripts/*.sh`.
