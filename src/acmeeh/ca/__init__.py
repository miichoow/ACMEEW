"""Pluggable CA backend system.

Exports the abstract base class, the structured error type, the result
dataclass, and the registry loader.
"""

from acmeeh.ca.base import CABackend, CAError, IssuedCertificate
from acmeeh.ca.registry import load_ca_backend

__all__ = [
    "CABackend",
    "CAError",
    "IssuedCertificate",
    "load_ca_backend",
]
