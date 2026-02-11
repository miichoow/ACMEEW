"""Tests for CSR profile management in AdminUserService."""

from __future__ import annotations

from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from acmeeh.admin.models import AuditLogEntry, CsrProfile
from acmeeh.admin.service import AdminUserService
from acmeeh.config.settings import AdminApiSettings

# ---------------------------------------------------------------------------
# Stub repositories
# ---------------------------------------------------------------------------


class StubCsrProfileRepo:
    """In-memory stub for CsrProfileRepository."""

    def __init__(self):
        self._profiles: dict[UUID, CsrProfile] = {}
        self._assignments: dict[UUID, UUID] = {}  # account_id → profile_id
        self._assigned_by: dict[UUID, UUID | None] = {}

    def create(self, entity: CsrProfile) -> CsrProfile:
        self._profiles[entity.id] = entity
        return entity

    def find_by_id(self, id_: UUID) -> CsrProfile | None:
        return self._profiles.get(id_)

    def delete(self, id_: UUID) -> bool:
        # cascade: remove associations
        to_remove = [a for a, p in self._assignments.items() if p == id_]
        for a in to_remove:
            del self._assignments[a]
            self._assigned_by.pop(a, None)
        return self._profiles.pop(id_, None) is not None

    def find_by_name(self, name: str) -> CsrProfile | None:
        for p in self._profiles.values():
            if p.name == name:
                return p
        return None

    def find_all_ordered(self) -> list[CsrProfile]:
        return sorted(
            self._profiles.values(),
            key=lambda p: p.created_at,
            reverse=True,
        )

    def update_profile(
        self,
        profile_id: UUID,
        name: str,
        description: str,
        profile_data: dict,
    ) -> CsrProfile | None:
        profile = self._profiles.get(profile_id)
        if profile is None:
            return None
        updated = replace(
            profile,
            name=name,
            description=description,
            profile_data=profile_data,
        )
        self._profiles[profile_id] = updated
        return updated

    def find_profile_for_account(self, account_id: UUID) -> CsrProfile | None:
        profile_id = self._assignments.get(account_id)
        if profile_id is None:
            return None
        return self._profiles.get(profile_id)

    def assign_to_account(
        self,
        profile_id: UUID,
        account_id: UUID,
        assigned_by: UUID | None = None,
    ) -> None:
        self._assignments[account_id] = profile_id
        self._assigned_by[account_id] = assigned_by

    def unassign_from_account(self, profile_id: UUID, account_id: UUID) -> None:
        if self._assignments.get(account_id) == profile_id:
            del self._assignments[account_id]
            self._assigned_by.pop(account_id, None)

    def find_accounts_for_profile(self, profile_id: UUID) -> list[UUID]:
        return [a for a, p in self._assignments.items() if p == profile_id]


class StubAuditLogRepo:
    def __init__(self):
        self.entries: list[AuditLogEntry] = []

    def create(self, entity: AuditLogEntry) -> AuditLogEntry:
        self.entries.append(entity)
        return entity

    def find_recent(self, limit=100):
        return self.entries[:limit]


class StubAdminUserRepo:
    def __init__(self):
        self._users = {}

    def count_all(self):
        return 0

    def find_by_id(self, id_):
        return None

    def find_all(self):
        return []


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_settings() -> AdminApiSettings:
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


SAMPLE_PROFILE_DATA = {
    "authorized_keys": {"RSA": 2048, "EC.secp256r1": 0},
    "authorized_signature_algorithms": ["SHA256withRSA", "SHA256withECDSA"],
    "wildcard_in_san": False,
    "san_minimum": 1,
    "san_maximum": 10,
}


@pytest.fixture()
def profile_repo():
    return StubCsrProfileRepo()


@pytest.fixture()
def audit_repo():
    return StubAuditLogRepo()


@pytest.fixture()
def service(profile_repo, audit_repo):
    return AdminUserService(
        StubAdminUserRepo(),
        audit_repo,
        _make_settings(),
        csr_profile_repo=profile_repo,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateCsrProfile:
    def test_create_basic(self, service, profile_repo):
        profile = service.create_csr_profile(
            "web-servers",
            SAMPLE_PROFILE_DATA,
            description="For web servers",
        )
        assert profile.name == "web-servers"
        assert profile.description == "For web servers"
        assert profile.profile_data == SAMPLE_PROFILE_DATA
        assert profile_repo.find_by_id(profile.id) is not None

    def test_create_strips_name(self, service):
        profile = service.create_csr_profile(
            "  padded  ",
            {"authorized_keys": {"RSA": 2048}},
        )
        assert profile.name == "padded"

    def test_duplicate_name_rejected(self, service):
        service.create_csr_profile("dup-name", SAMPLE_PROFILE_DATA)
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("dup-name", SAMPLE_PROFILE_DATA)
        assert exc_info.value.status == 409

    def test_empty_name_rejected(self, service):
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("", SAMPLE_PROFILE_DATA)
        assert exc_info.value.status == 400

    def test_invalid_regex_rejected(self, service):
        bad_data = {"common_name_regex": "[invalid("}
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("bad-regex", bad_data)
        assert exc_info.value.status == 400

    def test_invalid_authorized_keys_type_rejected(self, service):
        bad_data = {"authorized_keys": "not-a-dict"}
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("bad-ak", bad_data)
        assert exc_info.value.status == 400

    def test_invalid_boolean_field_rejected(self, service):
        bad_data = {"wildcard_in_san": "not-a-bool"}
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("bad-bool", bad_data)
        assert exc_info.value.status == 400

    def test_audit_log_entry(self, service, audit_repo):
        actor = uuid4()
        service.create_csr_profile("audit-test", SAMPLE_PROFILE_DATA, actor_id=actor)
        entries = [e for e in audit_repo.entries if e.action == "create_csr_profile"]
        assert len(entries) == 1
        assert entries[0].details["name"] == "audit-test"


class TestListCsrProfiles:
    def test_list_empty(self, service):
        profiles = service.list_csr_profiles()
        assert profiles == []

    def test_list_multiple(self, service):
        service.create_csr_profile("p1", SAMPLE_PROFILE_DATA)
        service.create_csr_profile("p2", SAMPLE_PROFILE_DATA)
        profiles = service.list_csr_profiles()
        assert len(profiles) == 2


class TestGetCsrProfile:
    def test_get_existing(self, service):
        created = service.create_csr_profile("get-test", SAMPLE_PROFILE_DATA)
        profile, acct_ids = service.get_csr_profile(created.id)
        assert profile.name == "get-test"
        assert acct_ids == []

    def test_get_nonexistent(self, service):
        with pytest.raises(Exception) as exc_info:
            service.get_csr_profile(uuid4())
        assert exc_info.value.status == 404

    def test_get_with_accounts(self, service):
        created = service.create_csr_profile("acct-test", SAMPLE_PROFILE_DATA)
        acct1 = uuid4()
        acct2 = uuid4()
        service.assign_profile_to_account(created.id, acct1)
        service.assign_profile_to_account(created.id, acct2)

        profile, acct_ids = service.get_csr_profile(created.id)
        assert set(acct_ids) == {acct1, acct2}


class TestUpdateCsrProfile:
    def test_update_basic(self, service):
        created = service.create_csr_profile("old-name", SAMPLE_PROFILE_DATA)
        new_data = {"authorized_keys": {"RSA": 4096}}
        updated = service.update_csr_profile(
            created.id,
            "new-name",
            new_data,
            description="Updated",
        )
        assert updated.name == "new-name"
        assert updated.description == "Updated"
        assert updated.profile_data == new_data

    def test_update_nonexistent(self, service):
        with pytest.raises(Exception) as exc_info:
            service.update_csr_profile(uuid4(), "name", SAMPLE_PROFILE_DATA)
        assert exc_info.value.status == 404

    def test_update_name_conflict(self, service):
        service.create_csr_profile("taken-name", SAMPLE_PROFILE_DATA)
        p2 = service.create_csr_profile("other-name", SAMPLE_PROFILE_DATA)
        with pytest.raises(Exception) as exc_info:
            service.update_csr_profile(p2.id, "taken-name", SAMPLE_PROFILE_DATA)
        assert exc_info.value.status == 409

    def test_update_same_name_ok(self, service):
        created = service.create_csr_profile("keep-name", SAMPLE_PROFILE_DATA)
        updated = service.update_csr_profile(
            created.id,
            "keep-name",
            {"authorized_keys": {"RSA": 4096}},
        )
        assert updated.name == "keep-name"

    def test_update_invalid_data_rejected(self, service):
        created = service.create_csr_profile("valid-first", SAMPLE_PROFILE_DATA)
        with pytest.raises(Exception) as exc_info:
            service.update_csr_profile(
                created.id,
                "valid-first",
                {"san_regex": "[bad("},
            )
        assert exc_info.value.status == 400

    def test_audit_log(self, service, audit_repo):
        created = service.create_csr_profile("upd-audit", SAMPLE_PROFILE_DATA)
        service.update_csr_profile(created.id, "upd-audit", SAMPLE_PROFILE_DATA)
        entries = [e for e in audit_repo.entries if e.action == "update_csr_profile"]
        assert len(entries) == 1


class TestDeleteCsrProfile:
    def test_delete_existing(self, service, profile_repo):
        created = service.create_csr_profile("del-test", SAMPLE_PROFILE_DATA)
        service.delete_csr_profile(created.id)
        assert profile_repo.find_by_id(created.id) is None

    def test_delete_nonexistent(self, service):
        with pytest.raises(Exception) as exc_info:
            service.delete_csr_profile(uuid4())
        assert exc_info.value.status == 404

    def test_audit_log(self, service, audit_repo):
        created = service.create_csr_profile("del-audit", SAMPLE_PROFILE_DATA)
        service.delete_csr_profile(created.id, actor_id=uuid4())
        entries = [e for e in audit_repo.entries if e.action == "delete_csr_profile"]
        assert len(entries) == 1


class TestAssignProfile:
    def test_assign(self, service, profile_repo):
        created = service.create_csr_profile("assign-test", SAMPLE_PROFILE_DATA)
        acct = uuid4()
        service.assign_profile_to_account(created.id, acct)
        assert profile_repo.find_profile_for_account(acct) is not None
        assert profile_repo.find_profile_for_account(acct).id == created.id

    def test_assign_replaces_existing(self, service, profile_repo):
        p1 = service.create_csr_profile("first-profile", SAMPLE_PROFILE_DATA)
        p2 = service.create_csr_profile("second-profile", SAMPLE_PROFILE_DATA)
        acct = uuid4()
        service.assign_profile_to_account(p1.id, acct)
        service.assign_profile_to_account(p2.id, acct)
        assert profile_repo.find_profile_for_account(acct).id == p2.id

    def test_assign_nonexistent_profile(self, service):
        with pytest.raises(Exception) as exc_info:
            service.assign_profile_to_account(uuid4(), uuid4())
        assert exc_info.value.status == 404

    def test_audit_log(self, service, audit_repo):
        created = service.create_csr_profile("assign-audit", SAMPLE_PROFILE_DATA)
        service.assign_profile_to_account(created.id, uuid4(), actor_id=uuid4())
        entries = [e for e in audit_repo.entries if e.action == "assign_csr_profile"]
        assert len(entries) == 1


class TestUnassignProfile:
    def test_unassign(self, service, profile_repo):
        created = service.create_csr_profile("unassign-test", SAMPLE_PROFILE_DATA)
        acct = uuid4()
        service.assign_profile_to_account(created.id, acct)
        service.unassign_profile_from_account(created.id, acct)
        assert profile_repo.find_profile_for_account(acct) is None

    def test_unassign_nonexistent_profile(self, service):
        with pytest.raises(Exception) as exc_info:
            service.unassign_profile_from_account(uuid4(), uuid4())
        assert exc_info.value.status == 404

    def test_audit_log(self, service, audit_repo):
        created = service.create_csr_profile("unassign-audit", SAMPLE_PROFILE_DATA)
        acct = uuid4()
        service.assign_profile_to_account(created.id, acct)
        service.unassign_profile_from_account(created.id, acct, actor_id=uuid4())
        entries = [e for e in audit_repo.entries if e.action == "unassign_csr_profile"]
        assert len(entries) == 1


class TestProfileDataSubdomainDepthValidation:
    """Validation of max_subdomain_depth and depth_base_domains in profile_data."""

    def test_max_subdomain_depth_must_be_integer(self, service):
        bad_data = {"max_subdomain_depth": "not-an-int"}
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("bad-depth-type", bad_data)
        assert exc_info.value.status == 400
        assert "integer" in str(exc_info.value).lower()

    def test_max_subdomain_depth_must_be_non_negative(self, service):
        bad_data = {"max_subdomain_depth": -1}
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("bad-depth-neg", bad_data)
        assert exc_info.value.status == 400
        assert ">= 0" in str(exc_info.value)

    def test_max_subdomain_depth_zero_ok(self, service):
        data = {"max_subdomain_depth": 0}
        profile = service.create_csr_profile("depth-zero", data)
        assert profile.profile_data["max_subdomain_depth"] == 0

    def test_depth_base_domains_must_be_list(self, service):
        bad_data = {"depth_base_domains": "not-a-list"}
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("bad-domains-type", bad_data)
        assert exc_info.value.status == 400
        assert "array" in str(exc_info.value).lower()

    def test_depth_base_domains_entries_must_be_nonempty_strings(self, service):
        bad_data = {"depth_base_domains": ["example.com", ""]}
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("bad-domain-empty", bad_data)
        assert exc_info.value.status == 400
        assert "non-empty string" in str(exc_info.value)

    def test_depth_base_domains_entries_must_be_strings(self, service):
        bad_data = {"depth_base_domains": [123]}
        with pytest.raises(Exception) as exc_info:
            service.create_csr_profile("bad-domain-int", bad_data)
        assert exc_info.value.status == 400
        assert "non-empty string" in str(exc_info.value)

    def test_valid_depth_config(self, service):
        data = {
            "max_subdomain_depth": 2,
            "depth_base_domains": ["corp.internal", "example.com"],
        }
        profile = service.create_csr_profile("good-depth", data)
        assert profile.profile_data["max_subdomain_depth"] == 2
        assert profile.profile_data["depth_base_domains"] == ["corp.internal", "example.com"]


class TestGetAccountCsrProfile:
    def test_no_profile_returns_none(self, service):
        assert service.get_account_csr_profile(uuid4()) is None

    def test_returns_assigned_profile(self, service):
        created = service.create_csr_profile("acct-profile", SAMPLE_PROFILE_DATA)
        acct = uuid4()
        service.assign_profile_to_account(created.id, acct)
        profile = service.get_account_csr_profile(acct)
        assert profile is not None
        assert profile.id == created.id
