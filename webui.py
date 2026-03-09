#!/usr/bin/env python3
"""Local web UI for captured LLM request/response logs."""

from __future__ import annotations

import csv
import io
import hashlib
import json
import os
import pathlib
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, make_response, request, send_from_directory


LOG_DIR = pathlib.Path(os.getenv("LOG_DIR", "logs")).resolve()
REQUESTS_DIR = LOG_DIR / "requests"
RESPONSES_DIR = LOG_DIR / "responses"

app = Flask(__name__, static_folder="webui/static", static_url_path="/static")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_dt(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _parse_time(ts: Any) -> datetime:
    if not isinstance(ts, str):
        return datetime.min
    text = ts.strip()
    if not text:
        return datetime.min
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return _normalize_dt(datetime.fromisoformat(text))
    except ValueError:
        return datetime.min


def _parse_time_filter(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    text = ts.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return _normalize_dt(datetime.fromisoformat(text))
    except ValueError:
        return None


def _load_json(path: pathlib.Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _parse_body_json(record: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not record:
        return None
    body = record.get("body")
    if not isinstance(body, Mapping):
        return None
    if body.get("encoding") != "utf-8":
        return None
    text = body.get("text")
    if not isinstance(text, str):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict):
        return parsed
    return None


def _deep_get(obj: Mapping[str, Any], *path: str) -> Optional[Any]:
    current: Any = obj
    for key in path:
        if not isinstance(current, Mapping):
            return None
        if key not in current:
            return None
        current = current[key]
    return current


def _safe_text(value: Any) -> Optional[str]:
    if isinstance(value, (str, int)):
        text = str(value).strip()
        if text:
            return text
    return None


def _detect_provider(host: str, path: str, payload: Optional[Dict[str, Any]]) -> str:
    host_l = (host or "").lower()
    path_l = (path or "").lower()

    if "azure" in host_l and "openai" in host_l:
        return "azure_openai"
    if "openai" in host_l:
        return "openai"
    if "anthropic" in host_l:
        return "anthropic"
    if "googleapis.com" in host_l and ("generativelanguage" in host_l or "/models/" in path_l):
        return "gemini"
    if "googleapis.com" in host_l and (":generatecontent" in path_l or ":streamgeneratecontent" in path_l):
        return "gemini"

    if path_l.startswith("/v1/messages"):
        return "anthropic"
    if "/openai/deployments/" in path_l:
        return "azure_openai"

    openai_compatible_paths = {
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/responses",
        "/v1/embeddings",
        "/v1/audio/transcriptions",
        "/v1/audio/speech",
    }
    if path_l in openai_compatible_paths:
        return "openai_compatible"

    if payload and isinstance(payload.get("anthropic_version"), str):
        return "anthropic"
    return "unknown"


def _extract_session_id_by_provider(provider: str, payload: Optional[Dict[str, Any]], headers: Mapping[str, Any]) -> Optional[str]:
    if not payload:
        payload = {}

    if provider in {"openai", "openai_compatible", "azure_openai"}:
        for key in ("session_id", "conversation_id", "thread_id", "chat_id", "user"):
            session_id = _safe_text(payload.get(key))
            if session_id:
                return session_id
        for path in (("metadata", "session_id"), ("metadata", "conversation_id"), ("metadata", "thread_id")):
            session_id = _safe_text(_deep_get(payload, *path))
            if session_id:
                return session_id

    if provider == "anthropic":
        for key in ("conversation_id", "session_id", "metadata"):
            if key == "metadata":
                session_id = _safe_text(_deep_get(payload, "metadata", "session_id"))
                if session_id:
                    return session_id
            else:
                session_id = _safe_text(payload.get(key))
                if session_id:
                    return session_id
        for header_key in ("anthropic-beta", "x-session-id"):
            session_id = _safe_text(headers.get(header_key))
            if session_id:
                return session_id

    if provider == "gemini":
        for path in (
            ("generationConfig", "cachedContent"),
            ("cachedContent",),
            ("systemInstruction", "parts", 0, "text"),
        ):
            value: Any = payload
            for segment in path:
                if isinstance(segment, int):
                    if isinstance(value, list) and 0 <= segment < len(value):
                        value = value[segment]
                    else:
                        value = None
                        break
                else:
                    if isinstance(value, Mapping) and segment in value:
                        value = value[segment]
                    else:
                        value = None
                        break
            session_id = _safe_text(value)
            if session_id:
                return session_id

    # provider-agnostic fallback
    for key in ("session_id", "conversation_id", "thread_id", "chat_id", "user"):
        session_id = _safe_text(payload.get(key))
        if session_id:
            return session_id

    # Fingerprint fallback: Skip 'system' prompts to differentiate conversations sharing the same instructions
    messages = payload.get("messages") or payload.get("contents")
    if not isinstance(messages, list) or not messages:
        return None

    targeted = None
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "system":
            continue
        targeted = m
        break
    
    if not targeted:
        targeted = messages[0]

    try:
        # Try to get content of the message to fingerprint the session
        text_to_hash = ""
        if isinstance(targeted, dict):
            # OpenAI / Anthropic
            content = targeted.get("content")
            if isinstance(content, str):
                text_to_hash = content
            elif isinstance(content, list):
                text_to_hash = json.dumps(content)
            # Gemini
            parts = targeted.get("parts")
            if isinstance(parts, list) and len(parts) > 0:
                text_to_hash = json.dumps(parts)

        if text_to_hash:
            # Use a short hash of the first non-system message as a session fingerprint
            h = hashlib.md5(text_to_hash.encode("utf-8")).hexdigest()[:12]
            return f"fp:{h}"
    except Exception:
        pass

    return None


def _extract_input_chars(payload: Optional[Dict[str, Any]]) -> int:
    if not payload:
        return 0

    total = 0

    def walk(node: Any) -> None:
        nonlocal total
        if isinstance(node, str):
            total += len(node)
            return
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if isinstance(node, dict):
            for value in node.values():
                walk(value)

    for key in ("messages", "input", "prompt", "contents", "system"):
        if key in payload:
            walk(payload[key])
    return total


def _safe_int(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    return None


def _load_all_flow_summaries() -> List[Dict[str, Any]]:
    events_path = LOG_DIR / "events.ndjson"
    if not events_path.exists():
        return []

    flows: Dict[str, Dict[str, Any]] = {}
    with events_path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
                flow_id = ev.get("flow_id")
                if not flow_id:
                    continue

                if flow_id not in flows:
                    flows[flow_id] = {
                        "flow_id": flow_id,
                        "timestamp": ev.get("timestamp"),
                        "provider": ev.get("provider", "unknown"),
                        "session_id": "none",
                        "method": None,
                        "url": None,
                        "path": None,
                        "server_host": None,
                        "model": None,
                        "input_chars_estimate": 0,
                        "request_body_size": 0,
                        "response_status": None,
                        "has_response": False,
                    }

                flow = flows[flow_id]
                event_type = ev.get("event")
                if event_type == "request":
                    flow["timestamp"] = ev.get("timestamp") or flow["timestamp"]
                    flow["provider"] = ev.get("provider") or flow["provider"]
                    flow["session_id"] = ev.get("session_id") or "none"
                    flow["method"] = ev.get("method")
                    flow["url"] = ev.get("url")
                    flow["server_host"] = ev.get("host")
                    flow["model"] = ev.get("model")
                    flow["input_chars_estimate"] = ev.get("input_chars_estimate") or 0
                elif event_type == "response":
                    flow["has_response"] = True
                    flow["response_status"] = ev.get("status_code")
            except json.JSONDecodeError:
                pass

    rows = list(flows.values())
    rows.sort(key=lambda r: _parse_time(r.get("timestamp")), reverse=True)
    return rows


def _load_flow_detail(flow_id: str) -> Optional[Dict[str, Any]]:
    req_path = REQUESTS_DIR / f"{flow_id}.json"
    resp_path = RESPONSES_DIR / f"{flow_id}.json"

    req = _load_json(req_path) if req_path.exists() else None
    if not req:
        return None
    resp = _load_json(resp_path) if resp_path.exists() else None

    return {
        "flow_id": flow_id,
        "request": req,
        "response": resp,
        "request_json": _parse_body_json(req),
        "response_json": _parse_body_json(resp),
        "request_file": str(req_path),
        "response_file": str(resp_path) if resp_path.exists() else None,
    }


def _filter_rows(
    rows: List[Dict[str, Any]],
    provider: str,
    session_id: str,
    from_raw: Optional[str],
    to_raw: Optional[str],
) -> List[Dict[str, Any]]:
    start = _parse_time_filter(from_raw)
    end = _parse_time_filter(to_raw)

    filtered = rows
    if provider != "all":
        filtered = [r for r in filtered if r.get("provider") == provider]
    if session_id != "all":
        filtered = [r for r in filtered if (r.get("session_id") or "none") == session_id]

    if start is not None:
        filtered = [r for r in filtered if _parse_time(r.get("timestamp")) >= start]
    if end is not None:
        filtered = [r for r in filtered if _parse_time(r.get("timestamp")) <= end]

    return filtered


@app.get("/")
def root() -> Any:
    return send_from_directory("webui/static", "index.html")


@app.get("/api/flows")
def api_flows() -> Any:
    provider = request.args.get("provider", "all")
    session_id = request.args.get("session_id", "all")
    from_ts = request.args.get("from")
    to_ts = request.args.get("to")
    limit_raw = request.args.get("limit", "200")

    try:
        limit = max(1, min(5000, int(limit_raw)))
    except ValueError:
        limit = 200

    rows = _load_all_flow_summaries()
    rows = _filter_rows(rows, provider, session_id, from_ts, to_ts)

    return jsonify({"flows": rows[:limit], "total": len(rows), "log_dir": str(LOG_DIR)})


@app.get("/api/flows/<flow_id>")
def api_flow_detail(flow_id: str) -> Any:
    detail = _load_flow_detail(flow_id)
    if not detail:
        return jsonify({"error": "flow not found"}), 404
    return jsonify(detail)


@app.get("/api/sessions")
def api_sessions() -> Any:
    provider = request.args.get("provider", "all")
    from_ts = request.args.get("from")
    to_ts = request.args.get("to")

    rows = _load_all_flow_summaries()
    rows = _filter_rows(rows, provider, "all", from_ts, to_ts)

    grouped: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "session_id": None,
            "count": 0,
            "providers": set(),
            "models": set(),
            "first_timestamp": None,
            "last_timestamp": None,
            "total_input_chars_estimate": 0,
        }
    )

    for row in rows:
        sid = row.get("session_id") or "none"
        item = grouped[sid]
        item["session_id"] = sid
        item["count"] += 1
        item["providers"].add(row.get("provider") or "unknown")
        model = row.get("model")
        if model:
            item["models"].add(model)

        ts = row.get("timestamp")
        if item["first_timestamp"] is None or _parse_time(ts) < _parse_time(item["first_timestamp"]):
            item["first_timestamp"] = ts
        if item["last_timestamp"] is None or _parse_time(ts) > _parse_time(item["last_timestamp"]):
            item["last_timestamp"] = ts

        chars = row.get("input_chars_estimate")
        if isinstance(chars, int):
            item["total_input_chars_estimate"] += chars

    sessions = []
    for sid, item in grouped.items():
        sessions.append(
            {
                "session_id": sid,
                "count": item["count"],
                "providers": sorted(item["providers"]),
                "models": sorted(item["models"]),
                "first_timestamp": item["first_timestamp"],
                "last_timestamp": item["last_timestamp"],
                "total_input_chars_estimate": item["total_input_chars_estimate"],
            }
        )

    sessions.sort(
        key=lambda s: (
            _parse_time(s.get("last_timestamp")),
            s.get("count", 0),
        ),
        reverse=True,
    )

    return jsonify({"sessions": sessions, "total": len(sessions)})


@app.get("/api/timeline")
def api_timeline() -> Any:
    provider = request.args.get("provider", "all")
    session_id = request.args.get("session_id", "all")
    from_ts = request.args.get("from")
    to_ts = request.args.get("to")

    rows = _load_all_flow_summaries()
    rows = _filter_rows(rows, provider, session_id, from_ts, to_ts)

    buckets: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"bucket": None, "count": 0, "session_ids": set(), "providers": set()}
    )

    for row in rows:
        ts = row.get("timestamp")
        bucket = "unknown"
        if isinstance(ts, str) and len(ts) >= 16:
            bucket = ts[:16]

        item = buckets[bucket]
        item["bucket"] = bucket
        item["count"] += 1
        sid = row.get("session_id") or "none"
        item["session_ids"].add(sid)
        item["providers"].add(row.get("provider") or "unknown")

    timeline = []
    for bucket, item in buckets.items():
        timeline.append(
            {
                "bucket": bucket,
                "count": item["count"],
                "session_count": len(item["session_ids"]),
                "providers": sorted(item["providers"]),
            }
        )

    timeline.sort(key=lambda b: b.get("bucket"), reverse=True)
    return jsonify({"timeline": timeline})


@app.get("/api/timeline_sessions")
def api_timeline_sessions() -> Any:
    provider = request.args.get("provider", "all")
    session_id = request.args.get("session_id", "all")
    from_ts = request.args.get("from")
    to_ts = request.args.get("to")

    rows = _load_all_flow_summaries()
    rows = _filter_rows(rows, provider, session_id, from_ts, to_ts)

    buckets: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"bucket": None, "count": 0, "providers": set(), "sessions": defaultdict(dict)}
    )

    for row in rows:
        ts = row.get("timestamp")
        bucket = "unknown"
        if isinstance(ts, str) and len(ts) >= 16:
            bucket = ts[:16]

        bkt = buckets[bucket]
        bkt["bucket"] = bucket
        bkt["count"] += 1
        bkt["providers"].add(row.get("provider") or "unknown")

        sid = row.get("session_id") or "none"
        if sid not in bkt["sessions"]:
            bkt["sessions"][sid] = {
                "session_id": sid,
                "count": 0,
                "providers": set(),
                "input_chars_estimate": 0,
                "flow_ids": [],
                "first_timestamp": None,
                "last_timestamp": None,
            }
        sess = bkt["sessions"][sid]
        sess["count"] += 1
        sess["providers"].add(row.get("provider") or "unknown")
        sess["flow_ids"].append(row.get("flow_id"))

        chars = row.get("input_chars_estimate")
        if isinstance(chars, int):
            sess["input_chars_estimate"] += chars

        row_ts = row.get("timestamp")
        if sess["first_timestamp"] is None or _parse_time(row_ts) < _parse_time(sess["first_timestamp"]):
            sess["first_timestamp"] = row_ts
        if sess["last_timestamp"] is None or _parse_time(row_ts) > _parse_time(sess["last_timestamp"]):
            sess["last_timestamp"] = row_ts

    timeline = []
    for bucket, bkt in buckets.items():
        sessions = []
        for sid, sess in bkt["sessions"].items():
            sessions.append(
                {
                    "session_id": sid,
                    "count": sess["count"],
                    "providers": sorted(sess["providers"]),
                    "input_chars_estimate": sess["input_chars_estimate"],
                    "flow_ids": [flow_id for flow_id in sess["flow_ids"] if isinstance(flow_id, str)],
                    "first_timestamp": sess["first_timestamp"],
                    "last_timestamp": sess["last_timestamp"],
                }
            )
        sessions.sort(key=lambda s: (s["count"], s["input_chars_estimate"]), reverse=True)

        timeline.append(
            {
                "bucket": bucket,
                "count": bkt["count"],
                "session_count": len(sessions),
                "providers": sorted(bkt["providers"]),
                "sessions": sessions,
            }
        )

    timeline.sort(key=lambda b: b.get("bucket"), reverse=True)
    return jsonify({"timeline_sessions": timeline})


@app.delete("/api/sessions/<path:session_id>")
def api_delete_session(session_id: str) -> Any:
    """Delete all flows belonging to a session."""
    rows = _load_all_flow_summaries()
    # Normalise: the URL arg 'none' maps to None session_ids
    target = None if session_id == "none" else session_id
    matching = [r for r in rows if (r.get("session_id") or None) == target]

    deleted = 0
    errors = []
    deleted_flow_ids = set()
    for row in matching:
        flow_id = row.get("flow_id")
        if not isinstance(flow_id, str):
            continue
        deleted_flow_ids.add(flow_id)
        for path in (REQUESTS_DIR / f"{flow_id}.json", RESPONSES_DIR / f"{flow_id}.json"):
            if path.exists():
                try:
                    path.unlink()
                    deleted += 1
                except OSError as exc:
                    errors.append(str(exc))

    if deleted_flow_ids:
        events_path = LOG_DIR / "events.ndjson"
        if events_path.exists():
            try:
                lines = []
                with events_path.open("r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            ev = json.loads(line)
                            if ev.get("flow_id") not in deleted_flow_ids:
                                lines.append(line)
                        except json.JSONDecodeError:
                            lines.append(line)
                tmp_path = events_path.with_suffix(".tmp")
                with tmp_path.open("w", encoding="utf-8") as f:
                    f.writelines(lines)
                tmp_path.replace(events_path)
            except OSError as exc:
                errors.append(str(exc))

    if errors:
        return jsonify({"deleted": deleted, "errors": errors}), 207
    return jsonify({"deleted": deleted, "session_id": session_id})


@app.get("/api/export")
def api_export() -> Any:
    export_format = request.args.get("format", "json").lower()
    provider = request.args.get("provider", "all")
    session_id = request.args.get("session_id", "all")
    from_ts = request.args.get("from")
    to_ts = request.args.get("to")
    include_details = request.args.get("include_details", "1") != "0"

    rows = _load_all_flow_summaries()
    rows = _filter_rows(rows, provider, session_id, from_ts, to_ts)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if export_format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "flow_id",
                "timestamp",
                "provider",
                "session_id",
                "method",
                "url",
                "path",
                "model",
                "input_chars_estimate",
                "response_status",
                "request_body_size",
                "has_response",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.get("flow_id"),
                    row.get("timestamp"),
                    row.get("provider"),
                    row.get("session_id") or "none",
                    row.get("method"),
                    row.get("url"),
                    row.get("path"),
                    row.get("model"),
                    row.get("input_chars_estimate"),
                    row.get("response_status"),
                    row.get("request_body_size"),
                    row.get("has_response"),
                ]
            )

        content = output.getvalue()
        response = make_response(content)
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="llm_export_{stamp}.csv"'
        return response

    if export_format != "json":
        return jsonify({"error": "unsupported format; use json or csv"}), 400

    payload: Dict[str, Any] = {
        "exported_at": _now_iso(),
        "filters": {
            "provider": provider,
            "session_id": session_id,
            "from": from_ts,
            "to": to_ts,
        },
        "count": len(rows),
        "flows": rows,
    }

    if include_details:
        details: List[Dict[str, Any]] = []
        for row in rows:
            flow_id = row.get("flow_id")
            if isinstance(flow_id, str):
                detail = _load_flow_detail(flow_id)
                if detail:
                    details.append(detail)
        payload["flow_details"] = details

    text = json.dumps(payload, ensure_ascii=False, indent=2)
    response = make_response(text)
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="llm_export_{stamp}.json"'
    return response


if __name__ == "__main__":
    host = os.getenv("WEBUI_HOST", "127.0.0.1")
    port = int(os.getenv("WEBUI_PORT", "8765"))
    app.run(host=host, port=port, debug=False)
