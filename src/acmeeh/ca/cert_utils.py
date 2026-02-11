"""Shared certificate-building helpers for CA backends.

Provides key-usage and extended-key-usage mappings used by both the
internal and HSM backends.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from acmeeh.ca.base import CAError

# ---------------------------------------------------------------------------
# Key usage / EKU mappings
# ---------------------------------------------------------------------------

_KEY_USAGE_FIELDS = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)

_EKU_OIDS = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
    "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
}


def build_key_usage(usages: tuple[str, ...]) -> x509.KeyUsage:
    """Build an :class:`x509.KeyUsage` extension from config strings."""
    usage_set = set(usages)
    ka = "key_agreement" in usage_set
    return x509.KeyUsage(
        digital_signature="digital_signature" in usage_set,
        content_commitment="content_commitment" in usage_set,
        key_encipherment="key_encipherment" in usage_set,
        data_encipherment="data_encipherment" in usage_set,
        key_agreement=ka,
        key_cert_sign="key_cert_sign" in usage_set,
        crl_sign="crl_sign" in usage_set,
        encipher_only="encipher_only" in usage_set if ka else False,
        decipher_only="decipher_only" in usage_set if ka else False,
    )


def build_eku(ekus: tuple[str, ...]) -> x509.ExtendedKeyUsage:
    """Build an :class:`x509.ExtendedKeyUsage` extension from config strings."""
    oids = []
    for name in ekus:
        oid = _EKU_OIDS.get(name)
        if oid is None:
            msg = f"Unknown extended key usage '{name}'; supported: {sorted(_EKU_OIDS)}"
            raise CAError(
                msg,
            )
        oids.append(oid)
    return x509.ExtendedKeyUsage(oids)
