"""HTTP entry point for PrivaCare."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .classifier import InvalidRequest, InvalidSchema
from .deidentifier import InvalidPolicy
from .reidentification import InvalidK, InvalidQuasiIdentifiers
from .service import Service

CLASSIFY_PATH = "/v1/classify"
DEIDENTIFY_PATH = "/v1/deidentify"
REIDENTIFICATION_RISK_PATH = "/v1/reidentification-risk"
KNOWN_POST_PATHS = (CLASSIFY_PATH, DEIDENTIFY_PATH, REIDENTIFICATION_RISK_PATH)


def env_address() -> tuple[str, int]:
    raw = os.environ.get("PRIVACARE_ADDR", "127.0.0.1:8080")
    host, _, port = raw.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"invalid PRIVACARE_ADDR: {raw!r}")
    return host, int(port)


class Handler(BaseHTTPRequestHandler):
    service = Service()

    def send_json(self, status: int, payload: dict, extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: int, code: str, message: str, extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.send_json(status, {"error": {"code": code, "message": message}}, extra_headers)

    def not_found(self) -> None:
        self.send_error_json(404, "not_found", f"no route for {self.path}")

    def method_not_allowed(self) -> None:
        self.send_error_json(
            405,
            "method_not_allowed",
            f"method not allowed for {self.path}",
            (("Allow", "POST"),),
        )

    def route_known_path(self) -> None:
        """405 for the known POST endpoints, 404 for anything else."""
        if self.path in KNOWN_POST_PATHS:
            self.method_not_allowed()
            return
        self.not_found()

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_json(200, self.service.health())
            return
        self.route_known_path()

    def do_POST(self) -> None:
        if self.path == CLASSIFY_PATH:
            self.handle_json_endpoint(self.service.classify)
            return
        if self.path == DEIDENTIFY_PATH:
            self.handle_json_endpoint(self.service.deidentify)
            return
        if self.path == REIDENTIFICATION_RISK_PATH:
            self.handle_json_endpoint(self.service.reidentification_risk, wrap_results=False)
            return
        self.not_found()

    def do_PUT(self) -> None:
        self.route_known_path()

    def do_DELETE(self) -> None:
        self.route_known_path()

    def do_PATCH(self) -> None:
        self.route_known_path()

    def handle_json_endpoint(self, handler, wrap_results: bool = True) -> None:
        """Shared JSON-body handling for the POST endpoints."""
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_error_json(415, "unsupported_media_type", "Content-Type must be application/json")
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            payload = json.loads(raw)
        except ValueError:
            self.send_error_json(400, "invalid_json", "request body is not valid JSON")
            return
        try:
            results = handler(payload)
        except InvalidRequest as exc:
            self.send_error_json(422, "invalid_request", str(exc))
            return
        except InvalidSchema as exc:
            self.send_error_json(422, "invalid_schema", str(exc))
            return
        except InvalidPolicy as exc:
            self.send_error_json(422, "invalid_policy", str(exc))
            return
        except InvalidQuasiIdentifiers as exc:
            self.send_error_json(422, "invalid_quasi_identifiers", str(exc))
            return
        except InvalidK as exc:
            self.send_error_json(422, "invalid_k", str(exc))
            return
        self.send_json(200, {"results": results} if wrap_results else results)

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
