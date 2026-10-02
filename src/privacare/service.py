"""Core service surface for PrivaCare.

The frozen baseline only reports process health. Later work adds the real
capabilities described in README.md behind this module; keep the public
surface here backward compatible.
"""

from __future__ import annotations

from . import __version__
from .classify import classify_records


class Service:
    """Health reporting plus sensitive-field classification."""

    name = "privacare"
    version = __version__

    def health(self) -> dict[str, str]:
        return {"status": "ok", "service": self.name, "version": self.version}

    def classify(self, records: list[dict], schema: dict | None = None) -> list[dict]:
        """Classify each record; results stay in input order."""
        fields_per_record = classify_records(records, schema)
        return [
            {"index": i, "fields": fields}
            for i, fields in enumerate(fields_per_record)
        ]
