"""Core service surface for PrivaCare.

Later work adds the real capabilities described in README.md behind this
module; keep the public surface here backward compatible.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .audit import audit_chain_request, audit_verify_request
from .classifier import classify_request
from .consent import consent_evaluate_request
from .deidentifier import deidentify_request
from .risk import reidentification_risk_request


class Service:
    """Health, classification, de-identification, risk, consent, audit."""

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

    def reidentification_risk(self, payload: Any) -> dict:
        """Measure k-anonymity re-identification risk in a request payload."""
        return reidentification_risk_request(payload)

    def evaluate_consent(self, payload: Any) -> list[dict]:
        """Evaluate accesses against consents in a /v1/consent/evaluate payload."""
        return consent_evaluate_request(payload)

    def audit_chain(self, payload: Any) -> dict:
        """Build an evidence chain for a /v1/audit/chain payload."""
        return audit_chain_request(payload)

    def audit_verify(self, payload: Any) -> dict:
        """Verify an evidence chain in a /v1/audit/verify payload."""
        return audit_verify_request(payload)
