"""PrivaCare - 医疗数据隐私与合规平台."""

from .consent_registry import (
    ALLOW,
    DENY,
    ConsentDecision,
    ConsentNotFoundError,
    ConsentRecord,
    ConsentRegistry,
    InvalidConsentError,
    InvalidConsentSnapshotError,
)

__version__ = "0.1.0"

__all__ = [
    "ALLOW",
    "DENY",
    "ConsentDecision",
    "ConsentNotFoundError",
    "ConsentRecord",
    "ConsentRegistry",
    "InvalidConsentError",
    "InvalidConsentSnapshotError",
    "__version__",
]
