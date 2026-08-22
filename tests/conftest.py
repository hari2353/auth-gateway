import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import pytest


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.keys import KeyStore

    return TestClient(create_app(key_store=KeyStore(initial_secret="test-secret-0")))
