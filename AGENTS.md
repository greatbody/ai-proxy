# AGENTS.md - Project Context for AI Proxy

> **CRITICAL MAINTENANCE DIRECTIVE**: As an AI assistant, you MUST update this file after every significant change to the project's logic, architecture, or configuration. Treat this file as your persistent memory. Keep it concise, focused on "why" and "how", and ensure it remains the source of truth for current project state.

## Project Purpose
This is a **High-Fidelity LLM Traffic Inspector**. It acts as an HTTPS interception proxy (using `mitmproxy`) to capture, log, and visualize communication between AI agents and LLM providers (OpenAI, DeepSeek, Anthropic, Gemini).

## Core Architecture
- **Interception**: `llm_capture_addon.py` - A Python script loaded by `mitmproxy`. It intercepts flows, detects providers, extracts session IDs/fingerprints, and logs data to `logs/events.ndjson` and individual JSON files in `logs/requests/` and `logs/responses/`.
- **Backend API**: `webui.py` - A Flask server that provides endpoints to query flows, sessions, and timeline data.
- **Frontend**: `webui/static/index.html` - A single-page Vanilla JS app with a dark "Studio" theme, 4-column resizable layout (Sessions | Timeline | Flows | Inspector), horizontal filter bar, tabbed inspector, and full 100vh utilization.

## Important Configurations
- **Wildcard Capture**: `CAPTURE_DOMAINS=*` is set in `.env` to intercept all traffic by default.
- **Certificate Trust**: The `mitmproxy` CA certificate must be trusted on the host for HTTPS interception to work. Command: `sudo security add-trusted-cert -d -p ssl -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem`.
- **Ports**:
  - MITM Proxy: `8080` (Standard)
  - Web UI: `8765` ([http://127.0.0.1:8765](http://127.0.0.1:8765))

## Key Recent Changes (Feb 22, 2026)
### 1. Full UI Overhaul
- **Dark Studio Theme**: GitHub-style dark palette (`#0d1117` bg, `#161b22` surfaces, `#30363d` borders).
- **4-Column Resizable Layout**: Sessions | Timeline | Flows | Inspector — all panels separated by drag-to-resize handles.
- **Horizontal Filter Bar**: Provider, Session, From, To, Limit, KPIs, and Export buttons all in a single compact top header.
- **Tabbed Inspector**: Split View / Request / Response tabs — maximizes content height.
- **Live Pulse Dot**: Green animated indicator in the header shows auto-refresh is active.
- **Better Flow Items**: Colored pills for method, status, and provider; monospace URL; model + chars on lower row.
- **Inter + JetBrains Mono** fonts loaded from Google Fonts.
- **Responsive Breakpoints**: Timeline panel hides at <1200px; Session panel hides at <900px.

### 2. Conversation Fingerprinting
- Implemented a grouping algorithm for sessions when no explicit ID is provided.
- **Algorithm**: It hashes the **first non-system message** (skipping shared "System Prompts") to create a stable `fp:<hash>` session ID.
- This ensures that separate conversations starting with the same instructions but different user inputs remain isolated.
- Logic is mirrored in both `llm_capture_addon.py` and `webui.py`.

### 3. Metadata Visibility
- The Web UI displays **Full URLs** in the flow list and **Full Headers** (Request/Response) in the inspector panels.

## How to Resume Work
1. Start the proxy: `./run_proxy.sh`
2. Start the UI: `./run_webui.sh`
3. Verify grouping logic: Open `webui.py` and `llm_capture_addon.py` and check `_extract_session_id`.
4. The UI is in `webui/static/index.html`. It uses a custom CSS grid system.

## Key Recent Changes (Feb 23, 2026)
### 4. Session Delete Feature
- **Delete icon**: A trash SVG icon appears on hover on each session row in the Sessions panel (`.session-del-btn`), positioned absolutely at the right edge.
- **Custom confirmation dialog**: A dark-themed modal overlay (`.modal-overlay` / `.modal-box`) is used rather than the native browser `confirm()`. It shows a red trash icon, the session ID + flow count, and Cancel/Delete buttons. It supports: backdrop click to dismiss, Escape key to dismiss, and is ARIA-labelled.
- **Backend endpoint**: `DELETE /api/sessions/<session_id>` in `webui.py` — scans all flow summaries for matching flows and deletes their request/response JSON files from `logs/requests/` and `logs/responses/`. Returns `{"deleted": N}`.
- **State cleanup**: After deletion, if the deleted session was the active filter, the filter resets to "all" and the inspector clears.

### 5. Frontend Polling & Performance Fixes
- **Debounced Fetching**: Added a `debounce` helper to prevent backend spamming when rapidly clicking between sessions or toggling filters.
- **Initial Load Auto-Select**: `refreshAll()` now loads sessions first and automatically selects the first session (if any) instead of fetching timeline and flows for "All Sessions" at startup. This prevents excessive and redundant fetch requests for massive data sets as soon as the UI loads.

### 6. Backend Performance & I/O Optimization
- **`events.ndjson` source of truth**: Modified `_load_all_flow_summaries()` in `webui.py`. Instead of iterating over the entire `logs/requests` JSON directory and reading/parsing thousands of JSON bodies per API call, it now reads the single `events.ndjson` log to instantly reconstruct the summaries.
- Reduced data payload fetch times from ~0.500 seconds to ~0.050 seconds for large pools of data.
- Deletion API route was also updated to slice removed IDs directly out of `events.ndjson` sequentially.

## Key Recent Changes (Mar 05, 2026)
### 7. Windows Startup Support
- Added `run_proxy.bat` and `run_webui.bat` for Windows to mirror the Unix launch scripts: optional venv activation, `.env` loading, then start mitmproxy or the Flask web UI.
- README now documents Windows manual startup commands and notes that the mitmproxy CA must be trusted in Windows to capture HTTPS traffic.
