"""Tests for CSR profile dry-run validation via AdminUserService.validate_csr."""

from __future__ import annotations

import base64
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acmeeh.admin.models import AdminUser, AuditLogEntry, CsrProfile
from acmeeh.admin.service import AdminUserService
from acmeeh.app.errors import AcmeProblem
from acmeeh.config.settings import AdminApiSettings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _admin_settings() -> AdminApiSettings:
    return AdminApiSettings(
        enabled=True,
        base_path="/api",
        token_secret="test-secret",
        token_expiry_seconds=3600,
        initial_admin_email="admin@example.com",
        password_length=20,
        default_page_size=50,
        max_page_size=1000,
    )


def _build_csr(
    key=None,
    cn="example.com",
    sans=None,
) -> x509.CertificateSigningRequest:
    """Build a CSR for testing."""
    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_attrs = []
    if cn:
        subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject_attrs))
    if sans:
        san_names = [x509.DNSName(s) for s in sans]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


def _csr_to_b64(csr: x509.CertificateSigningRequest) -> str:
    """Encode CSR as base64-DER."""
    return base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode("ascii")


# ---------------------------------------------------------------------------
# Stub repositories
# ---------------------------------------------------------------------------


class StubUserRepo:
    def __init__(self):
        self._users: dict[UUID, AdminUser] = {}

    def create(self, entity):
        self._users[entity.id] = entity
        return entity

    def find_by_id(self, id_):
        return self._users.get(id_)

    def find_by_username(self, username):
        for u in self._users.values():
            if u.username == username:
                return u
        return None

    def find_all(self):
        return list(self._users.values())

    def count_all(self):
        return len(self._users)


class StubAuditRepo:
    def __init__(self):
        self._entries: list[AuditLogEntry] = []

    def create(self, entry):
        self._entries.append(entry)

    def find_recent(self, limit):
        return self._entries[:limit]

    def search(self, filters, limit):
        return self._entries[:limit]

    def delete_older_than(self, max_age_days):
        return 0


class StubCsrProfileRepo:
    def __init__(self):
        self._profiles: dict[UUID, CsrProfile] = {}

    def create(self, profile):
        self._profiles[profile.id] = profile
        return profile

    def find_by_id(self, profile_id) -> CsrProfile | None:
        return self._profiles.get(profile_id)

    def find_by_name(self, name) -> CsrProfile | None:
        for p in self._profiles.values():
            if p.name == name:
                return p
        return None

    def find_all_ordered(self):
        return list(self._profiles.values())

    def find_accounts_for_profile(self, profile_id):
        return []

    def update_profile(self, profile_id, name, description, profile_data):
        old = self._profiles[profile_id]
        from dataclasses import replace

        updated = replace(old, name=name, description=description, profile_data=profile_data)
        self._profiles[profile_id] = updated
        return updated

    def delete(self, profile_id):
        self._profiles.pop(profile_id, None)

    def assign_to_account(self, profile_id, account_id, actor_id):
        pass

    def unassign_from_account(self, profile_id, account_id):
        pass

    def find_profile_for_account(self, account_id):
        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def csr_profile_repo():
    return StubCsrProfileRepo()


@pytest.fixture
def service(csr_profile_repo):
    return AdminUserService(
        user_repo=StubUserRepo(),
        audit_repo=StubAuditRepo(),
        settings=_admin_settings(),
        csr_profile_repo=csr_profile_repo,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestConformingCSR:
    """Conforming CSR -> valid=true, violations=[]."""

    def test_valid_csr_passes(self, service, csr_profile_repo):
        profile = CsrProfile(
            id=uuid4(),
            name="test-profile",
            profile_data={"authorized_keys": {"RSA": 2048}},
        )
        csr_profile_repo.create(profile)

        csr = _build_csr(sans=["example.com"])
        result = service.validate_csr(profile.id, _csr_to_b64(csr))

        assert result["valid"] is True
        assert result["violations"] == []

    def test_empty_profile_passes_any_csr(self, service, csr_profile_repo):
        profile = CsrProfile(
            id=uuid4(),
            name="permissive",
            profile_data={},
        )
        csr_profile_repo.create(profile)

        csr = _build_csr(cn="*.anything.com", sans=["*.anything.com", "a.com", "b.com"])
        result = service.validate_csr(profile.id, _csr_to_b64(csr))

        assert result["valid"] is True
        assert result["violations"] == []


class TestNonConformingCSR:
    """Non-conforming CSR -> valid=false with violations list."""

    def test_wrong_key_type(self, service, csr_profile_repo):
        profile = CsrProfile(
            id=uuid4(),
            name="ec-only",
            profile_data={"authorized_keys": {"EC.secp256r1": 0}},
        )
        csr_profile_repo.create(profile)

        # Build RSA CSR when only EC is allowed
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = _build_csr(key=key, sans=["example.com"])
        result = service.validate_csr(profile.id, _csr_to_b64(csr))

        assert result["valid"] is False
        assert len(result["violations"]) > 0
        assert any("Key type" in v for v in result["violations"])

    def test_wildcard_not_allowed(self, service, csr_profile_repo):
        profile = CsrProfile(
            id=uuid4(),
            name="no-wildcard",
            profile_data={"wildcard_in_san": False},
        )
        csr_profile_repo.create(profile)

        csr = _build_csr(sans=["*.example.com"])
        result = service.validate_csr(profile.id, _csr_to_b64(csr))

        assert result["valid"] is False
        assert len(result["violations"]) > 0

    def test_multiple_violations(self, service, csr_profile_repo):
        profile = CsrProfile(
            id=uuid4(),
            name="strict",
            profile_data={
                "authorized_keys": {"EC.secp256r1": 0},
                "wildcard_in_san": False,
                "san_maximum": 1,
            },
        )
        csr_profile_repo.create(profile)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = _build_csr(key=key, sans=["*.a.com", "b.com"])
        result = service.validate_csr(profile.id, _csr_to_b64(csr))

        assert result["valid"] is False
        assert len(result["violations"]) >= 2


class TestProfileNotFound:
    """Profile not found -> 404 error."""

    def test_missing_profile_raises_404(self, service):
        csr = _build_csr(sans=["example.com"])
        with pytest.raises(AcmeProblem) as exc_info:
            service.validate_csr(uuid4(), _csr_to_b64(csr))
        assert exc_info.value.status == 404


class TestInvalidBase64:
    """Invalid base64 in CSR -> 400 error."""

    def test_invalid_base64_raises_400(self, service, csr_profile_repo):
        profile = CsrProfile(
            id=uuid4(),
            name="test",
            profile_data={},
        )
        csr_profile_repo.create(profile)

        with pytest.raises(AcmeProblem) as exc_info:
            service.validate_csr(profile.id, "not-valid-base64!!!")
        assert exc_info.value.status == 400
        assert "base64" in exc_info.value.detail.lower()


class TestInvalidDER:
    """Invalid DER in CSR -> 400 error."""

    def test_invalid_der_raises_400(self, service, csr_profile_repo):
        profile = CsrProfile(
            id=uuid4(),
            name="test",
            profile_data={},
        )
        csr_profile_repo.create(profile)

        # Valid base64, but not a valid DER CSR
        bad_der_b64 = base64.b64encode(b"this is not DER").decode("ascii")
        with pytest.raises(AcmeProblem) as exc_info:
            service.validate_csr(profile.id, bad_der_b64)
        assert exc_info.value.status == 400
        assert "parse" in exc_info.value.detail.lower() or "CSR" in exc_info.value.detail
