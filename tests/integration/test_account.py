"""Integration tests for ACME account management."""


def test_create_account(client, jws):
    """POST /new-account creates a new account."""
    resp = jws.post(
        client,
        "/new-account",
        {
            "termsOfServiceAgreed": True,
            "contact": ["mailto:test@example.com"],
        },
        use_kid=False,
    )

    assert resp.status_code == 201
    data = resp.get_json()
    assert data["status"] == "valid"
    assert "Location" in resp.headers
