"""Core service surface for PrivaCare.

Later work adds the real capabilities described in README.md behind this
module; keep the public surface here backward compatible.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .access import access_evaluate_request
from .aggregate import aggregate_query_request
from .audit import audit_chain_request, audit_verify_request
from .classifier import classify_request
from .compliance import transfer_evaluate_request
from .consent import consent_evaluate_request
from .deidentifier import deidentify_request
from .differential import differential_aggregate_request
from .encryption import decrypt_request, encrypt_request, rotate_request
from .lineage import trace_lineage_request
from .pseudonymizer import pseudonymize_request
from .risk import reidentification_risk_request


class Service:
    """Health reporting, classification, de-identification, risk, consent."""

    name = "privacare"
    version = __version__

    def health(self) -> dict[str, str]:
        return {"status": "ok", "service": self.name, "version": self.version}

    def classify(self, payload: Any) -> list[dict]:
        """Classify sensitive fields in a /v1/classify request payload."""
        return classify_request(payload)

    def deidentify(self, payload: Any) -> list[dict]:
        """De-identify records in a /v1/deidentify request payload."""
        return deidentify_request(payload)

    def pseudonymize(self, payload: Any) -> list[dict]:
        """Pseudonymize records in a /v1/pseudonymize request payload."""
        return pseudonymize_request(payload)

    def reidentification_risk(self, payload: Any) -> dict:
        """Measure k-anonymity re-identification risk in a request payload."""
        return reidentification_risk_request(payload)

    def evaluate_consent(self, payload: Any) -> list[dict]:
        """Evaluate accesses against consents in a /v1/consent/evaluate payload."""
        return consent_evaluate_request(payload)

    def evaluate_access(self, payload: Any) -> list[dict]:
        """Evaluate accesses against grants in a /v1/access/evaluate payload."""
        return access_evaluate_request(payload)

    def audit_chain(self, payload: Any) -> dict:
        """Build a tamper-evident evidence chain for a /v1/audit/chain payload."""
        return audit_chain_request(payload)

    def audit_verify(self, payload: Any) -> dict:
        """Recompute and check an evidence chain for a /v1/audit/verify payload."""
        return audit_verify_request(payload)

    def trace_lineage(self, payload: Any) -> dict:
        """Trace upstream/downstream dataset lineage for a /v1/lineage/trace payload."""
        return trace_lineage_request(payload)

    def encrypt(self, payload: Any) -> list[dict]:
        """Encrypt record fields for a /v1/encryption/encrypt payload."""
        return encrypt_request(payload)

    def decrypt(self, payload: Any) -> list[dict]:
        """Decrypt record envelopes for a /v1/encryption/decrypt payload."""
        return decrypt_request(payload)

    def rotate_encryption(self, payload: Any) -> list[dict]:
        """Re-encrypt record envelopes for a /v1/encryption/rotate payload."""
        return rotate_request(payload)

    def aggregate_query(self, payload: Any) -> dict:
        """Run a small-group protected /v1/query/aggregate payload."""
        return aggregate_query_request(payload)

    def differential_aggregate(self, payload: Any) -> dict:
        """Run a differentially private /v1/query/differential-aggregate payload."""
        return differential_aggregate_request(payload)

    def evaluate_transfer(self, payload: Any) -> list[dict]:
        """Evaluate transfers against rules in a /v1/compliance/transfer/evaluate payload."""
        return transfer_evaluate_request(payload)
