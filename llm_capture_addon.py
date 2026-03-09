#!/usr/bin/env python3
"""Mitmproxy addon to capture LLM API traffic for selected domains.

Usage (with mitmdump):
  mitmdump -s llm_capture_addon.py --set block_global=false

Configuration via environment variables:
  CAPTURE_DOMAINS      Comma-separated domain allowlist. Default: api.openai.com
  LOG_DIR              Directory for logs. Default: ./logs
  SAVE_RESPONSES       true/false. Default: true
  REDACT_AUTH          true/false. Default: true
  MAX_BODY_BYTES       Max bytes to store per request/response body. Default: 2097152
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mitmproxy import http


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LLMCaptureAddon:
    def __init__(self) -> None:
        domains = os.getenv("CAPTURE_DOMAINS", "*")
        self.allowed_domains = [d.strip().lower() for d in domains.split(",") if d.strip()]

        log_dir = os.getenv("LOG_DIR", "logs")
        self.log_root = pathlib.Path(log_dir).resolve()
        self.log_root.mkdir(parents=True, exist_ok=True)

        self.reqs_dir = self.log_root / "requests"
        self.resp_dir = self.log_root / "responses"
        self.reqs_dir.mkdir(parents=True, exist_ok=True)
        self.resp_dir.mkdir(parents=True, exist_ok=True)

        self.events_path = self.log_root / "events.ndjson"
        self.save_responses = _env_bool("SAVE_RESPONSES", True)
        self.redact_auth = _env_bool("REDACT_AUTH", True)
        self.max_body_bytes = int(os.getenv("MAX_BODY_BYTES", "2097152"))

        print("[llm-capture] enabled")
        print(f"[llm-capture] domains={self.allowed_domains}")
        print(f"[llm-capture] log_dir={self.log_root}")

    def _detect_provider(self, host: str, path: str, payload: Optional[Dict[str, Any]]) -> str:
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

    def _parse_json_body(self, body: Dict[str, object]) -> Optional[Dict[str, Any]]:
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

    def _deep_get(self, obj: Mapping[str, Any], *path: str) -> Optional[Any]:
        current: Any = obj
        for key in path:
            if not isinstance(current, Mapping):
                return None
            if key not in current:
                return None
            current = current[key]
        return current

    def _safe_text(self, value: Any) -> Optional[str]:
        if isinstance(value, (str, int)):
            text = str(value).strip()
            if text:
                return text
        return None

    def _extract_session_id(
        self,
        provider: str,
        payload: Optional[Dict[str, Any]],
        headers: Mapping[str, Any],
    ) -> Optional[str]:
        if not payload:
            payload = {}

        if provider in {"openai", "openai_compatible", "azure_openai"}:
            for key in ("session_id", "conversation_id", "thread_id", "chat_id", "user"):
                value = self._safe_text(payload.get(key))
                if value:
                    return value
            for path in (("metadata", "session_id"), ("metadata", "conversation_id"), ("metadata", "thread_id")):
                value = self._safe_text(self._deep_get(payload, *path))
                if value:
                    return value

        if provider == "anthropic":
            for key in ("conversation_id", "session_id"):
                value = self._safe_text(payload.get(key))
                if value:
                    return value
            value = self._safe_text(self._deep_get(payload, "metadata", "session_id"))
            if value:
                return value
            for header_key in ("anthropic-beta", "x-session-id"):
                value = self._safe_text(headers.get(header_key))
                if value:
                    return value

        if provider == "gemini":
            for path in (("generationConfig", "cachedContent"), ("cachedContent",)):
                value = self._safe_text(self._deep_get(payload, *path))
                if value:
                    return value

        for key in ("session_id", "conversation_id", "thread_id", "chat_id", "user"):
            value = self._safe_text(payload.get(key))
            if value:
                return value

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

    def _extract_request_summary(self, payload: Optional[Dict[str, Any]]) -> Dict[str, object]:
        summary: Dict[str, object] = {
            "model": None,
            "operation": None,
            "input_chars_estimate": 0,
        }
        if not payload:
            return summary

        model = payload.get("model")
        if isinstance(model, str) and model.strip():
            summary["model"] = model.strip()

        if "messages" in payload:
            summary["operation"] = "chat.completions"
        elif "input" in payload:
            summary["operation"] = "responses"
        elif "prompt" in payload:
            summary["operation"] = "completions"

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

        for key in ("messages", "input", "prompt"):
            if key in payload:
                walk(payload[key])

        summary["input_chars_estimate"] = total
        return summary

    def _is_allowed(self, host: str) -> bool:
        if "*" in self.allowed_domains:
            return True
        host = (host or "").lower()
        if not host:
            return False
        for domain in self.allowed_domains:
            if host == domain or host.endswith(f".{domain}"):
                return True
        return False

    def _safe_headers(self, headers: http.Headers) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for key, value in headers.items(multi=False):
            if self.redact_auth and key.lower() == "authorization":
                out[key] = "<redacted>"
            else:
                out[key] = value
        return out

    def _body_record(self, raw: bytes) -> Dict[str, object]:
        truncated = False
        original_size = len(raw)
        if original_size > self.max_body_bytes:
            raw = raw[: self.max_body_bytes]
            truncated = True

        try:
            text = raw.decode("utf-8")
            return {
                "encoding": "utf-8",
                "text": text,
                "truncated": truncated,
                "original_size": original_size,
                "stored_size": len(raw),
            }
        except UnicodeDecodeError:
            b64 = base64.b64encode(raw).decode("ascii")
            return {
                "encoding": "base64",
                "base64": b64,
                "truncated": truncated,
                "original_size": original_size,
                "stored_size": len(raw),
            }

    def _append_event(self, payload: Dict[str, object]) -> None:
        with self.events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host or ""
        if not self._is_allowed(host):
            return

        flow_id = flow.id
        request_body = self._body_record(flow.request.raw_content or b"")
        request_payload = self._parse_json_body(request_body)
        provider = self._detect_provider(host, flow.request.path, request_payload)
        session_id = self._extract_session_id(
            provider,
            request_payload,
            self._safe_headers(flow.request.headers),
        )
        req_summary = self._extract_request_summary(request_payload)
        record = {
            "event": "request",
            "timestamp": _now_iso(),
            "flow_id": flow_id,
            "provider": provider,
            "session_id": session_id,
            "server_host": host,
            "server_port": flow.request.port,
            "scheme": flow.request.scheme,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "http_version": flow.request.http_version,
            "headers": self._safe_headers(flow.request.headers),
            "body": request_body,
            "summary": req_summary,
        }

        # Only persist full request JSON for recognised AI providers
        req_file_str: Optional[str] = None
        if provider != "unknown":
            req_file = self.reqs_dir / f"{flow_id}.json"
            req_file.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
            req_file_str = str(req_file)

        # Always append a lightweight summary event
        self._append_event(
            {
                "event": "request",
                "timestamp": record["timestamp"],
                "flow_id": flow_id,
                "provider": provider,
                "session_id": session_id,
                "method": flow.request.method,
                "host": host,
                "url": flow.request.pretty_url,
                "model": req_summary.get("model"),
                "input_chars_estimate": req_summary.get("input_chars_estimate"),
                "request_file": req_file_str,
            }
        )

    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host or ""
        if not self._is_allowed(host):
            return
        if not self.save_responses:
            return
        if flow.response is None:
            return

        flow_id = flow.id
        response_body = self._body_record(flow.response.raw_content or b"")
        response_payload = self._parse_json_body(response_body)
        provider = self._detect_provider(host, flow.request.path, response_payload)

        response_id: Optional[str] = None
        if response_payload:
            value = response_payload.get("id")
            if isinstance(value, (str, int)):
                as_text = str(value).strip()
                if as_text:
                    response_id = as_text

        record = {
            "event": "response",
            "timestamp": _now_iso(),
            "flow_id": flow_id,
            "provider": provider,
            "server_host": host,
            "status_code": flow.response.status_code,
            "reason": flow.response.reason,
            "http_version": flow.response.http_version,
            "headers": self._safe_headers(flow.response.headers),
            "body": response_body,
            "summary": {
                "response_id": response_id,
            },
        }

        # Only persist full response JSON for recognised AI providers
        resp_file_str: Optional[str] = None
        if provider != "unknown":
            resp_file = self.resp_dir / f"{flow_id}.json"
            resp_file.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
            resp_file_str = str(resp_file)

        # Always append a lightweight summary event
        self._append_event(
            {
                "event": "response",
                "timestamp": record["timestamp"],
                "flow_id": flow_id,
                "provider": provider,
                "host": host,
                "status_code": flow.response.status_code,
                "response_id": response_id,
                "response_file": resp_file_str,
            }
        )


addons: List[LLMCaptureAddon] = [LLMCaptureAddon()]
