"""Unit tests for acmeeh.core.jws — JWS parsing, verification, and JWK utilities."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils

from acmeeh.app.errors import AcmeProblem
from acmeeh.core.jws import (
    JWSObject,
    _b64url_decode,
    _b64url_encode,
    compute_thumbprint,
    jwk_to_public_key,
    key_authorization,
    parse_jws,
    validate_eab_jws,
    validate_key_policy,
    validate_protected_header,
    verify_signature,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_jws_body(protected: dict, payload, signature: bytes = b"\x00") -> bytes:
    """Build a JWS Flattened JSON body from components."""
    prot_b64 = _b64(json.dumps(protected).encode())
    if payload is None:
        pay_b64 = ""
    elif isinstance(payload, bytes):
        pay_b64 = _b64(payload)
    else:
        pay_b64 = _b64(json.dumps(payload).encode())
    sig_b64 = _b64(signature)
    return json.dumps(
        {
            "protected": prot_b64,
            "payload": pay_b64,
            "signature": sig_b64,
        }
    ).encode()


def _generate_ec_key(curve=ec.SECP256R1):
    return ec.generate_private_key(curve())


def _generate_rsa_key(size=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def _ec_jwk(key) -> dict:
    """Extract the public JWK dict from an EC private key."""
    pub = key.public_key()
    nums = pub.public_numbers()
    curve_name = {
        "secp256r1": "P-256",
        "secp384r1": "P-384",
        "secp521r1": "P-521",
    }[pub.curve.name]
    size = {
        "P-256": 32,
        "P-384": 48,
        "P-521": 66,
    }[curve_name]
    return {
        "kty": "EC",
        "crv": curve_name,
        "x": _b64(nums.x.to_bytes(size, "big")),
        "y": _b64(nums.y.to_bytes(size, "big")),
    }


def _rsa_jwk(key) -> dict:
    """Extract the public JWK dict from an RSA private key."""
    pub = key.public_key()
    nums = pub.public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "n": _b64(n_bytes),
        "e": _b64(e_bytes),
    }


# ---------------------------------------------------------------------------
# TestB64url
# ---------------------------------------------------------------------------


class TestB64url:
    def test_round_trip(self):
        data = b"hello world"
        assert _b64url_decode(_b64url_encode(data)) == data

    def test_missing_padding_handled(self):
        # Produce a base64url string that needs padding
        data = b"ab"
        encoded = _b64url_encode(data)
        assert "=" not in encoded
        assert _b64url_decode(encoded) == data

    def test_empty_input(self):
        assert _b64url_encode(b"") == ""
        assert _b64url_decode("") == b""


# ---------------------------------------------------------------------------
# TestParseJws
# ---------------------------------------------------------------------------


class TestParseJws:
    def test_valid_jws(self):
        body = _make_jws_body({"alg": "ES256"}, {"foo": "bar"})
        jws = parse_jws(body)
        assert jws.protected_header["alg"] == "ES256"
        assert jws.payload == {"foo": "bar"}

    def test_missing_protected(self):
        raw = json.dumps({"payload": "", "signature": ""}).encode()
        with pytest.raises(AcmeProblem, match="missing required field 'protected'"):
            parse_jws(raw)

    def test_missing_payload(self):
        raw = json.dumps({"protected": _b64(b'{"alg":"ES256"}'), "signature": ""}).encode()
        with pytest.raises(AcmeProblem, match="missing required field 'payload'"):
            parse_jws(raw)

    def test_missing_signature(self):
        raw = json.dumps({"protected": _b64(b'{"alg":"ES256"}'), "payload": ""}).encode()
        with pytest.raises(AcmeProblem, match="missing required field 'signature'"):
            parse_jws(raw)

    def test_non_json_body(self):
        with pytest.raises(AcmeProblem, match="not valid JSON"):
            parse_jws(b"not json")

    def test_non_dict_body(self):
        with pytest.raises(AcmeProblem, match="must be a JSON object"):
            parse_jws(b'["list"]')

    def test_invalid_base64_header(self):
        raw = json.dumps({"protected": "!!!invalid!!!", "payload": "", "signature": ""}).encode()
        with pytest.raises(AcmeProblem, match="Cannot decode JWS protected header"):
            parse_jws(raw)

    def test_non_dict_header(self):
        raw = json.dumps(
            {
                "protected": _b64(b'"just a string"'),
                "payload": "",
                "signature": _b64(b"\x00"),
            }
        ).encode()
        with pytest.raises(AcmeProblem, match="protected header must be a JSON object"):
            parse_jws(raw)

    def test_empty_payload_post_as_get(self):
        body = _make_jws_body({"alg": "ES256"}, None)
        jws = parse_jws(body)
        assert jws.is_post_as_get
        assert jws.payload is None


# ---------------------------------------------------------------------------
# TestJWSObject
# ---------------------------------------------------------------------------


class TestJWSObject:
    def _make(self, **header_overrides):
        header = {"alg": "ES256", "nonce": "abc", "url": "https://example.com/acme"}
        header.update(header_overrides)
        return JWSObject(
            protected_header=header,
            protected_b64="x",
            payload=None,
            payload_b64="",
            signature=b"\x00",
            signature_b64="AA",
        )

    def test_algorithm(self):
        assert self._make().algorithm == "ES256"

    def test_nonce(self):
        assert self._make().nonce == "abc"

    def test_url(self):
        assert self._make().url == "https://example.com/acme"

    def test_kid(self):
        assert self._make(kid="https://acme/acct/1").kid == "https://acme/acct/1"

    def test_kid_absent(self):
        assert self._make().kid is None

    def test_jwk(self):
        jwk = {"kty": "EC"}
        assert self._make(jwk=jwk).jwk == jwk

    def test_is_post_as_get_true(self):
        assert self._make().is_post_as_get is True

    def test_is_post_as_get_false(self):
        obj = JWSObject(
            protected_header={"alg": "ES256"},
            protected_b64="x",
            payload={"a": 1},
            payload_b64="notempty",
            signature=b"\x00",
            signature_b64="AA",
        )
        assert obj.is_post_as_get is False


# ---------------------------------------------------------------------------
# TestValidateProtectedHeader
# ---------------------------------------------------------------------------


class TestValidateProtectedHeader:
    BASE = {"alg": "ES256", "nonce": "n1", "url": "https://example.com", "jwk": {"kty": "EC"}}

    def test_valid_header(self):
        validate_protected_header(self.BASE)

    def test_missing_alg(self):
        h = {**self.BASE}
        del h["alg"]
        with pytest.raises(AcmeProblem, match="missing 'alg'"):
            validate_protected_header(h)

    def test_unsupported_alg(self):
        h = {**self.BASE, "alg": "NONE"}
        with pytest.raises(AcmeProblem, match="Unsupported algorithm"):
            validate_protected_header(h)

    def test_alg_not_in_allowed_list(self):
        h = {**self.BASE, "alg": "RS256"}
        with pytest.raises(AcmeProblem, match="not allowed by server policy"):
            validate_protected_header(h, allowed_algorithms=["ES256"])

    def test_missing_nonce_when_required(self):
        h = {**self.BASE}
        del h["nonce"]
        with pytest.raises(AcmeProblem, match="missing 'nonce'"):
            validate_protected_header(h, require_nonce=True)

    def test_nonce_not_required(self):
        h = {**self.BASE}
        del h["nonce"]
        validate_protected_header(h, require_nonce=False)

    def test_missing_url(self):
        h = {**self.BASE}
        del h["url"]
        with pytest.raises(AcmeProblem, match="missing 'url'"):
            validate_protected_header(h)

    def test_url_mismatch(self):
        with pytest.raises(AcmeProblem, match="url.*mismatch"):
            validate_protected_header(self.BASE, request_url="https://other.com")

    def test_kid_jwk_mutual_exclusion(self):
        h = {**self.BASE, "kid": "https://acme/acct/1", "jwk": {"kty": "EC"}}
        with pytest.raises(AcmeProblem, match="must not contain both"):
            validate_protected_header(h)

    def test_require_kid_without_kid(self):
        h = {**self.BASE}  # has jwk, not kid
        with pytest.raises(AcmeProblem, match="missing 'kid'"):
            validate_protected_header(h, require_kid=True)

    def test_require_jwk_without_jwk(self):
        h = {**self.BASE}
        del h["jwk"]
        h["kid"] = "https://acme/acct/1"
        with pytest.raises(AcmeProblem, match="missing 'jwk'"):
            validate_protected_header(h, require_jwk=True)

    def test_neither_kid_nor_jwk(self):
        h = {**self.BASE}
        del h["jwk"]
        with pytest.raises(AcmeProblem, match="must contain either"):
            validate_protected_header(h)


# ---------------------------------------------------------------------------
# TestJwkToPublicKey
# ---------------------------------------------------------------------------


class TestJwkToPublicKey:
    def test_valid_rsa_jwk(self):
        key = _generate_rsa_key()
        jwk = _rsa_jwk(key)
        pub = jwk_to_public_key(jwk)
        assert isinstance(pub, rsa.RSAPublicKey)

    def test_valid_ec_p256(self):
        key = _generate_ec_key(ec.SECP256R1)
        jwk = _ec_jwk(key)
        pub = jwk_to_public_key(jwk)
        assert isinstance(pub, ec.EllipticCurvePublicKey)

    def test_valid_ec_p384(self):
        key = _generate_ec_key(ec.SECP384R1)
        jwk = _ec_jwk(key)
        pub = jwk_to_public_key(jwk)
        assert isinstance(pub, ec.EllipticCurvePublicKey)

    def test_valid_ec_p521(self):
        key = _generate_ec_key(ec.SECP521R1)
        jwk = _ec_jwk(key)
        pub = jwk_to_public_key(jwk)
        assert isinstance(pub, ec.EllipticCurvePublicKey)

    def test_unsupported_curve(self):
        with pytest.raises(AcmeProblem, match="Unsupported EC curve"):
            jwk_to_public_key({"kty": "EC", "crv": "P-192", "x": "AA", "y": "AA"})

    def test_unsupported_kty(self):
        with pytest.raises(AcmeProblem, match="Unsupported key type"):
            jwk_to_public_key({"kty": "OKP"})

    def test_malformed_rsa(self):
        with pytest.raises(AcmeProblem, match="Invalid RSA JWK"):
            jwk_to_public_key({"kty": "RSA", "n": "!!!", "e": "!!!"})

    def test_malformed_ec(self):
        with pytest.raises(AcmeProblem, match="Invalid EC JWK"):
            jwk_to_public_key({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"})


# ---------------------------------------------------------------------------
# TestValidateKeyPolicy
# ---------------------------------------------------------------------------


class TestValidateKeyPolicy:
    class _FakeSecuritySettings:
        def __init__(
            self,
            min_rsa=2048,
            max_rsa=8192,
            allowed_ec=("P-256", "P-384", "P-521"),
        ):
            self.min_rsa_key_size = min_rsa
            self.max_rsa_key_size = max_rsa
            self.allowed_ec_curves = allowed_ec

    def test_rsa_below_min(self):
        key = _generate_rsa_key(2048)
        jwk = _rsa_jwk(key)
        with pytest.raises(AcmeProblem, match="below minimum"):
            validate_key_policy(jwk, self._FakeSecuritySettings(min_rsa=4096))

    def test_rsa_above_max(self):
        key = _generate_rsa_key(4096)
        jwk = _rsa_jwk(key)
        with pytest.raises(AcmeProblem, match="exceeds maximum"):
            validate_key_policy(jwk, self._FakeSecuritySettings(max_rsa=2048))

    def test_bad_rsa_exponent_too_small(self):
        # Craft a JWK with e=3 (too small)
        jwk = {"kty": "RSA", "n": _b64(b"\x00" * 256), "e": _b64(b"\x03")}
        with pytest.raises(AcmeProblem, match="not acceptable"):
            validate_key_policy(jwk, self._FakeSecuritySettings())

    def test_bad_rsa_exponent_even(self):
        # Even exponent
        jwk = {"kty": "RSA", "n": _b64(b"\x00" * 256), "e": _b64((65538).to_bytes(3, "big"))}
        with pytest.raises(AcmeProblem, match="not acceptable"):
            validate_key_policy(jwk, self._FakeSecuritySettings())

    def test_ec_curve_not_allowed(self):
        key = _generate_ec_key(ec.SECP384R1)
        jwk = _ec_jwk(key)
        with pytest.raises(AcmeProblem, match="not allowed"):
            validate_key_policy(jwk, self._FakeSecuritySettings(allowed_ec=("P-256",)))

    def test_valid_rsa_key(self):
        key = _generate_rsa_key(2048)
        jwk = _rsa_jwk(key)
        validate_key_policy(jwk, self._FakeSecuritySettings())  # no exception

    def test_valid_ec_key(self):
        key = _generate_ec_key(ec.SECP256R1)
        jwk = _ec_jwk(key)
        validate_key_policy(jwk, self._FakeSecuritySettings())  # no exception


# ---------------------------------------------------------------------------
# TestVerifySignature
# ---------------------------------------------------------------------------


class TestVerifySignature:
    @patch("acmeeh.logging.security_events.jws_signature_failed")
    def test_valid_es256(self, mock_se):
        key = _generate_ec_key(ec.SECP256R1)
        jwk = _ec_jwk(key)
        payload = {"test": True}
        prot_b64 = _b64(json.dumps({"alg": "ES256"}).encode())
        pay_b64 = _b64(json.dumps(payload).encode())
        signing_input = f"{prot_b64}.{pay_b64}".encode("ascii")

        # Sign
        der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        jws = JWSObject(
            protected_header={"alg": "ES256"},
            protected_b64=prot_b64,
            payload=payload,
            payload_b64=pay_b64,
            signature=raw_sig,
            signature_b64=_b64(raw_sig),
        )
        verify_signature(jws, key.public_key())  # should not raise

    @patch("acmeeh.logging.security_events.jws_signature_failed")
    def test_valid_rs256(self, mock_se):
        from cryptography.hazmat.primitives.asymmetric import padding

        key = _generate_rsa_key()
        prot_b64 = _b64(json.dumps({"alg": "RS256"}).encode())
        pay_b64 = _b64(json.dumps({"test": True}).encode())
        signing_input = f"{prot_b64}.{pay_b64}".encode("ascii")

        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

        jws = JWSObject(
            protected_header={"alg": "RS256"},
            protected_b64=prot_b64,
            payload={"test": True},
            payload_b64=pay_b64,
            signature=sig,
            signature_b64=_b64(sig),
        )
        verify_signature(jws, key.public_key())  # should not raise

    def test_rsa_alg_with_ec_key(self):
        ec_key = _generate_ec_key()
        jws = JWSObject(
            protected_header={"alg": "RS256"},
            protected_b64="x",
            payload=None,
            payload_b64="",
            signature=b"\x00" * 32,
            signature_b64="x",
        )
        with pytest.raises(AcmeProblem, match="requires an RSA key"):
            verify_signature(jws, ec_key.public_key())

    def test_ec_alg_with_rsa_key(self):
        rsa_key = _generate_rsa_key()
        jws = JWSObject(
            protected_header={"alg": "ES256"},
            protected_b64="x",
            payload=None,
            payload_b64="",
            signature=b"\x00" * 64,
            signature_b64="x",
        )
        with pytest.raises(AcmeProblem, match="requires an EC key"):
            verify_signature(jws, rsa_key.public_key())

    def test_ec_curve_alg_mismatch(self):
        key = _generate_ec_key(ec.SECP384R1)
        jws = JWSObject(
            protected_header={"alg": "ES256"},
            protected_b64="x",
            payload=None,
            payload_b64="",
            signature=b"\x00" * 64,
            signature_b64="x",
        )
        with pytest.raises(AcmeProblem, match="requires curve P-256"):
            verify_signature(jws, key.public_key())

    def test_wrong_ec_signature_length(self):
        key = _generate_ec_key(ec.SECP256R1)
        jws = JWSObject(
            protected_header={"alg": "ES256"},
            protected_b64="x",
            payload=None,
            payload_b64="",
            signature=b"\x00" * 63,  # wrong length
            signature_b64="x",
        )
        with pytest.raises(AcmeProblem, match="incorrect length"):
            verify_signature(jws, key.public_key())

    @patch("acmeeh.logging.security_events.jws_signature_failed")
    def test_invalid_signature_bytes(self, mock_se):
        key = _generate_ec_key(ec.SECP256R1)
        jws = JWSObject(
            protected_header={"alg": "ES256"},
            protected_b64=_b64(b'{"alg":"ES256"}'),
            payload=None,
            payload_b64="",
            signature=b"\x00" * 64,
            signature_b64="x",
        )
        with pytest.raises(AcmeProblem, match="signature verification failed"):
            verify_signature(jws, key.public_key())


# ---------------------------------------------------------------------------
# TestComputeThumbprint
# ---------------------------------------------------------------------------


class TestComputeThumbprint:
    def test_ec_canonical_order(self):
        key = _generate_ec_key()
        jwk = _ec_jwk(key)
        tp = compute_thumbprint(jwk)
        # Verify manually
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = _b64(hashlib.sha256(canonical.encode()).digest())
        assert tp == expected

    def test_rsa_canonical_order(self):
        key = _generate_rsa_key()
        jwk = _rsa_jwk(key)
        tp = compute_thumbprint(jwk)
        canonical = json.dumps(
            {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = _b64(hashlib.sha256(canonical.encode()).digest())
        assert tp == expected

    def test_unsupported_kty(self):
        with pytest.raises(AcmeProblem, match="Cannot compute thumbprint"):
            compute_thumbprint({"kty": "OKP"})

    def test_deterministic(self):
        key = _generate_ec_key()
        jwk = _ec_jwk(key)
        assert compute_thumbprint(jwk) == compute_thumbprint(jwk)


# ---------------------------------------------------------------------------
# TestValidateEabJws
# ---------------------------------------------------------------------------


class TestValidateEabJws:
    def _build_eab(self, outer_jwk, hmac_key_bytes, kid="eab-kid-1", alg="HS256"):
        """Build a valid EAB inner JWS."""
        header = {"alg": alg, "kid": kid, "url": "https://acme/new-account"}
        header_b64 = _b64(json.dumps(header).encode())
        payload_b64 = _b64(json.dumps(outer_jwk).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        sig = hmac.new(hmac_key_bytes, signing_input, "sha256").digest()
        sig_b64 = _b64(sig)
        return {
            "protected": header_b64,
            "payload": payload_b64,
            "signature": sig_b64,
        }

    @patch("acmeeh.logging.security_events.jws_signature_failed")
    def test_valid_eab(self, mock_se):
        key = _generate_ec_key()
        jwk = _ec_jwk(key)
        hmac_key = b"supersecrethmackey1234567890abcde"
        hmac_key_b64 = _b64(hmac_key)
        eab = self._build_eab(jwk, hmac_key)
        kid = validate_eab_jws(eab, jwk, hmac_key_b64)
        assert kid == "eab-kid-1"

    def test_wrong_algorithm(self):
        key = _generate_ec_key()
        jwk = _ec_jwk(key)
        hmac_key = b"supersecrethmackey1234567890abcde"
        hmac_key_b64 = _b64(hmac_key)
        eab = self._build_eab(jwk, hmac_key, alg="HS384")
        with pytest.raises(AcmeProblem, match="must use HS256"):
            validate_eab_jws(eab, jwk, hmac_key_b64)

    def test_missing_kid(self):
        header = {"alg": "HS256", "url": "https://acme/new-account"}
        header_b64 = _b64(json.dumps(header).encode())
        eab = {"protected": header_b64, "payload": _b64(b"{}"), "signature": _b64(b"\x00")}
        with pytest.raises(AcmeProblem, match="missing 'kid'"):
            validate_eab_jws(eab, {}, _b64(b"key"))

    @patch("acmeeh.logging.security_events.jws_signature_failed")
    def test_payload_mismatch(self, mock_se):
        key = _generate_ec_key()
        jwk = _ec_jwk(key)
        different_jwk = {"kty": "EC", "crv": "P-256", "x": "different", "y": "different"}
        hmac_key = b"supersecrethmackey1234567890abcde"
        hmac_key_b64 = _b64(hmac_key)
        # Build EAB with different_jwk as payload but pass jwk as outer
        eab = self._build_eab(different_jwk, hmac_key)
        with pytest.raises(AcmeProblem, match="does not match"):
            validate_eab_jws(eab, jwk, hmac_key_b64)

    @patch("acmeeh.logging.security_events.jws_signature_failed")
    def test_invalid_hmac(self, mock_se):
        key = _generate_ec_key()
        jwk = _ec_jwk(key)
        hmac_key = b"supersecrethmackey1234567890abcde"
        wrong_key = b"wrongkeywrongkeywrongkeywrongkey1"
        eab = self._build_eab(jwk, hmac_key)
        with pytest.raises(AcmeProblem, match="HMAC signature verification failed"):
            validate_eab_jws(eab, jwk, _b64(wrong_key))

    def test_missing_required_fields(self):
        with pytest.raises(AcmeProblem, match="missing required fields"):
            validate_eab_jws({"protected": "", "payload": "", "signature": ""}, {}, "")


# ---------------------------------------------------------------------------
# TestKeyAuthorization
# ---------------------------------------------------------------------------


class TestKeyAuthorization:
    def test_format(self):
        key = _generate_ec_key()
        jwk = _ec_jwk(key)
        token = "testtoken123"
        ka = key_authorization(token, jwk)
        thumbprint = compute_thumbprint(jwk)
        assert ka == f"{token}.{thumbprint}"
