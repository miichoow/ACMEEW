"""Integration tests for nonce management."""


def test_head_new_nonce(client):
    """HEAD /new-nonce returns a Replay-Nonce header."""
    resp = client.head("/new-nonce")
    assert resp.status_code == 200
    assert "Replay-Nonce" in resp.headers


def test_get_new_nonce(client):
    """GET /new-nonce returns 204 with a Replay-Nonce header."""
    resp = client.get("/new-nonce")
    # The nonce endpoint returns 200 or 204
    assert resp.status_code in (200, 204)
    assert "Replay-Nonce" in resp.headers


def test_nonces_are_unique(client):
    """Each nonce request should produce a unique value."""
    nonces = set()
    for _ in range(5):
        resp = client.head("/new-nonce")
        nonce = resp.headers.get("Replay-Nonce")
        assert nonce is not None
        nonces.add(nonce)
    assert len(nonces) == 5
