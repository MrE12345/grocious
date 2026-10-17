import base64
import io
import json
import uuid

import coop_archive
from coop_session import load_headers


def test_login_tokens_bootstrap_persistent_device(tmp_path):
    tokens = tmp_path / "coop_tokens.json"
    tokens.write_text(json.dumps({"access_token": "first"}))
    first = load_headers(tmp_path)
    assert first["x-token"] == "first"
    uuid.UUID(first["x-deviceid"])
    assert first["user-agent"] == "Android(15)/Coop(4.31.0/6871)"
    tokens.write_text(json.dumps({"access_token": "second"}))
    second = load_headers(tmp_path)
    assert second["x-token"] == "second"
    assert second["x-deviceid"] == first["x-deviceid"]
    assert json.loads((tmp_path / "coop_session.json").read_text())["headers"] == second


def test_existing_device_and_client_settings_survive(tmp_path):
    saved = {"X-DeviceId": "existing-device", "User-Agent": "custom-client", "Host": "old-host"}
    (tmp_path / "coop_session.json").write_text(json.dumps({"headers": saved}))
    headers = load_headers(tmp_path)
    assert headers["x-deviceid"] == "existing-device"
    assert headers["user-agent"] == "custom-client"
    assert "host" not in headers


def test_refresh_keeps_required_headers_and_persists_new_token(tmp_path, monkeypatch):
    (tmp_path / "coop_tokens.json").write_text(json.dumps({"access_token": "old", "refresh_token": "refresh"}))
    monkeypatch.setattr(coop_archive, "DATA", tmp_path)
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "test-member"}).encode()).decode().rstrip("=")
    renewed = "header." + payload + ".signature"
    def reply(request, timeout):
        assert json.loads(request.data)["grant_type"] == "refresh_token"
        return io.BytesIO(json.dumps({"access_token": renewed}).encode())
    monkeypatch.setattr(coop_archive.urllib.request, "urlopen", reply)
    client = coop_archive.Client()
    assert client.headers["x-token"] == renewed
    assert client.headers["user-agent"].startswith("Android(")
    assert client.headers["x-deviceid"]
    assert json.loads((tmp_path / "coop_session.json").read_text())["headers"] == client.headers
    assert json.loads((tmp_path / "coop_tokens.json").read_text())["refresh_token"] == "refresh"
