"""Integration tests for the ACME directory endpoint."""


def test_get_directory(client):
    """GET /directory returns all required URLs."""
    resp = client.get("/directory")
    assert resp.status_code == 200

    data = resp.get_json()
    assert "newNonce" in data
    assert "newAccount" in data
    assert "newOrder" in data
    assert "newAuthz" in data
    assert "revokeCert" in data
    assert "keyChange" in data


def test_directory_urls_contain_base(client):
    """Directory URLs should contain the external base URL."""
    resp = client.get("/directory")
    data = resp.get_json()
    for key in ("newNonce", "newAccount", "newOrder"):
        assert data[key].startswith("https://acme.test")
