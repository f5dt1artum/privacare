"""Core service surface for PrivaCare.

Later work adds the real capabilities described in README.md behind this
module; keep the public surface here backward compatible.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .classifier import classify_request
from .deidentifier import deidentify_request
from .reidentification import reidentification_risk_request


class Service:
    """Health reporting, field classification, de-identification, and
    re-identification risk evaluation."""

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
        """Evaluate k-anonymity for a /v1/reidentification-risk payload."""
        return reidentification_risk_request(payload)
