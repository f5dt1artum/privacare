"""HTTP entry point for PrivaCare."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .access import InvalidAccess as InvalidAccessEntry
from .access import InvalidGrant
from .audit import InvalidAnchor, InvalidAuditEvent, InvalidEvidenceChain
from .classifier import InvalidRequest, InvalidSchema
from .consent import InvalidAccess, InvalidConsent
from .deidentifier import InvalidPolicy
from .encryption import InvalidCiphertext, InvalidEnvelope
from .lineage import InvalidDataset, InvalidQuery, InvalidTransfer
from .pseudonymizer import InvalidContext, InvalidFields, InvalidKey
from .risk import InvalidK, InvalidQuasiIdentifiers
from .service import Service

CLASSIFY_PATH = "/v1/classify"
DEIDENTIFY_PATH = "/v1/deidentify"
PSEUDONYMIZE_PATH = "/v1/pseudonymize"
RISK_PATH = "/v1/reidentification-risk"
CONSENT_PATH = "/v1/consent/evaluate"
ACCESS_PATH = "/v1/access/evaluate"
AUDIT_CHAIN_PATH = "/v1/audit/chain"
AUDIT_VERIFY_PATH = "/v1/audit/verify"
LINEAGE_TRACE_PATH = "/v1/lineage/trace"
ENCRYPT_PATH = "/v1/encryption/encrypt"
DECRYPT_PATH = "/v1/encryption/decrypt"
ROTATE_PATH = "/v1/encryption/rotate"
KNOWN_POST_PATHS = (
    CLASSIFY_PATH,
    DEIDENTIFY_PATH,
    PSEUDONYMIZE_PATH,
    RISK_PATH,
    CONSENT_PATH,
    ACCESS_PATH,
    AUDIT_CHAIN_PATH,
    AUDIT_VERIFY_PATH,
    LINEAGE_TRACE_PATH,
    ENCRYPT_PATH,
    DECRYPT_PATH,
    ROTATE_PATH,
)


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
        if self.path == PSEUDONYMIZE_PATH:
            self.handle_json_endpoint(self.service.pseudonymize)
            return
        if self.path == RISK_PATH:
            self.handle_json_endpoint(self.service.reidentification_risk, wrap_results=False)
            return
        if self.path == CONSENT_PATH:
            self.handle_json_endpoint(self.service.evaluate_consent)
            return
        if self.path == ACCESS_PATH:
            self.handle_json_endpoint(self.service.evaluate_access)
            return
        if self.path == AUDIT_CHAIN_PATH:
            self.handle_json_endpoint(self.service.audit_chain, wrap_results=False)
            return
        if self.path == AUDIT_VERIFY_PATH:
            self.handle_json_endpoint(self.service.audit_verify, wrap_results=False)
            return
        if self.path == LINEAGE_TRACE_PATH:
            self.handle_json_endpoint(self.service.trace_lineage, wrap_results=False)
            return
        if self.path == ENCRYPT_PATH:
            self.handle_json_endpoint(self.service.encrypt)
            return
        if self.path == DECRYPT_PATH:
            self.handle_json_endpoint(self.service.decrypt)
            return
        if self.path == ROTATE_PATH:
            self.handle_json_endpoint(self.service.rotate_encryption)
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
            output = handler(payload)
        except InvalidRequest as exc:
            self.send_error_json(422, "invalid_request", str(exc))
            return
        except InvalidSchema as exc:
            self.send_error_json(422, "invalid_schema", str(exc))
            return
        except InvalidPolicy as exc:
            self.send_error_json(422, "invalid_policy", str(exc))
            return
        except InvalidFields as exc:
            self.send_error_json(422, "invalid_fields", str(exc))
            return
        except InvalidKey as exc:
            self.send_error_json(422, "invalid_key", str(exc))
            return
        except InvalidContext as exc:
            self.send_error_json(422, "invalid_context", str(exc))
            return
        except InvalidQuasiIdentifiers as exc:
            self.send_error_json(422, "invalid_quasi_identifiers", str(exc))
            return
        except InvalidK as exc:
            self.send_error_json(422, "invalid_k", str(exc))
            return
        except InvalidConsent as exc:
            self.send_error_json(422, "invalid_consent", str(exc))
            return
        except InvalidAccess as exc:
            self.send_error_json(422, "invalid_access", str(exc))
            return
        except InvalidGrant as exc:
            self.send_error_json(422, "invalid_grant", str(exc))
            return
        except InvalidAccessEntry as exc:
            self.send_error_json(422, "invalid_access", str(exc))
            return
        except InvalidAuditEvent as exc:
            self.send_error_json(422, "invalid_audit_event", str(exc))
            return
        except InvalidAnchor as exc:
            self.send_error_json(422, "invalid_anchor", str(exc))
            return
        except InvalidEvidenceChain as exc:
            self.send_error_json(422, "invalid_evidence_chain", str(exc))
            return
        except InvalidDataset as exc:
            self.send_error_json(422, "invalid_dataset", str(exc))
            return
        except InvalidTransfer as exc:
            self.send_error_json(422, "invalid_transfer", str(exc))
            return
        except InvalidQuery as exc:
            self.send_error_json(422, "invalid_query", str(exc))
            return
        except InvalidEnvelope as exc:
            self.send_error_json(422, "invalid_envelope", str(exc))
            return
        except InvalidCiphertext as exc:
            self.send_error_json(422, "invalid_ciphertext", str(exc))
            return
        self.send_json(200, {"results": output} if wrap_results else output)

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
