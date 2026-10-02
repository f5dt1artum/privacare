"""HTTP entry point for PrivaCare."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .classify import SchemaError
from .service import Service

CLASSIFY_PATH = "/v1/classify"


def env_address() -> tuple[str, int]:
    raw = os.environ.get("PRIVACARE_ADDR", "127.0.0.1:8080")
    host, _, port = raw.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"invalid PRIVACARE_ADDR: {raw!r}")
    return host, int(port)


class Handler(BaseHTTPRequestHandler):
    service = Service()

    def send_json(self, status: int, payload: dict, headers: dict | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_error_json(self, status: int, code: str, message: str,
                        headers: dict | None = None) -> None:
        self.send_json(status, {"error": {"code": code, "message": message}}, headers)

    def not_found(self) -> None:
        self.send_error_json(404, "not_found", f"no route for {self.path}")

    def method_not_allowed(self) -> None:
        self.send_error_json(
            405,
            "method_not_allowed",
            f"{self.command} is not allowed for {CLASSIFY_PATH}",
            {"Allow": "POST"},
        )

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_json(200, self.service.health())
            return
        if self.path == CLASSIFY_PATH:
            self.method_not_allowed()
            return
        self.not_found()

    def do_POST(self) -> None:
        if self.path == CLASSIFY_PATH:
            self.handle_classify()
            return
        self.not_found()

    def do_PUT(self) -> None:
        self._other_method()

    def do_DELETE(self) -> None:
        self._other_method()

    def do_PATCH(self) -> None:
        self._other_method()

    def do_HEAD(self) -> None:
        self._other_method()

    def do_OPTIONS(self) -> None:
        self._other_method()

    def _other_method(self) -> None:
        if self.path == CLASSIFY_PATH:
            self.method_not_allowed()
            return
        self.not_found()

    # ------------------------------------------------------------------

    def handle_classify(self) -> None:
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            self.send_error_json(
                415, "unsupported_media_type", "Content-Type must be application/json"
            )
            return

        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length else 0
        except ValueError:
            length = 0
        raw = self.rfile.read(max(length, 0)) if length > 0 else b""
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_error_json(400, "invalid_json", "request body is not valid JSON")
            return

        if not isinstance(body, dict):
            self.send_error_json(422, "invalid_request", "request body must be a JSON object")
            return
        records = body.get("records")
        if not isinstance(records, list) or not records:
            self.send_error_json(422, "invalid_request", "records must be a non-empty array")
            return
        if any(not isinstance(item, dict) for item in records):
            self.send_error_json(422, "invalid_request", "each record must be a JSON object")
            return
        schema = body.get("schema", {})
        if not isinstance(schema, dict):
            self.send_error_json(422, "invalid_schema", "schema must be a JSON object")
            return

        try:
            results = self.service.classify(records, schema)
        except SchemaError as exc:
            self.send_error_json(422, "invalid_schema", str(exc))
            return
        self.send_json(200, {"results": results})

    def log_message(self, fmt: str, *args: object) -> None:
        """Silence per-request logging so recorded output stays stable."""


def main() -> int:
    parser = argparse.ArgumentParser(prog="privacare.server", description="医疗数据隐私与合规平台")
    host, port = env_address()
    parser.add_argument("--host", default=host)
    parser.add_argument("--port", type=int, default=port)
    args = parser.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"PrivaCare listening on http://{args.host}:{httpd.server_address[1]}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
