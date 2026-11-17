import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import pytest


@pytest.fixture(autouse=True)
def _reset_mfa_state():
    """USERS is a module-level in-memory store, so MFA enrollment leaks
    across tests (a fresh app still sees the old factor). Reset the MFA
    fields after every test; passwords/tenants/scopes stay as shipped."""
    from auth_gateway import audit, users

    yield
    audit.clear()
    for record in users.USERS.values():
        record["totp_secret"] = None
        record["totp_pending"] = None
        record["recovery_codes"] = []
        record["recovery_used"] = set()


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.keys import KeyStore

    return TestClient(create_app(key_store=KeyStore(initial_secret="test-secret-0")))
