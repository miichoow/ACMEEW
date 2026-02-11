"""CA management subcommands."""

from __future__ import annotations

import logging
import sys

log = logging.getLogger(__name__)


def run_ca(config, args) -> None:
    """Handle ca subcommands."""
    if args.ca_command == "test-sign":
        _ca_test_sign(config)
    else:
        sys.exit(1)


def _ca_test_sign(config) -> None:
    """Sign an ephemeral CSR to verify CA backend is working."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from acmeeh.ca.registry import load_ca_backend
    from acmeeh.config.settings import _DEFAULT_PROFILE

    try:
        backend = load_ca_backend(config.settings.ca)
        backend.startup_check()
    except Exception:
        sys.exit(1)

    # Generate ephemeral key + CSR
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "test.acmeeh.internal"),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("test.acmeeh.internal"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    try:
        backend.sign(
            csr,
            profile=_DEFAULT_PROFILE,
            validity_days=1,
        )
    except Exception:
        sys.exit(1)
