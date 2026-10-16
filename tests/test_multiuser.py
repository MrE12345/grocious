"""Cross-user access, worker scope, session revocation and concurrent storage regressions."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import threading

import pytest

import accounts
import navigation
import receipt_archive as archive
import runtime
import webgui
from inbox import store

PASSWORD = "a-long-local-test-password"


@contextmanager
def as_user(identity):
    token = runtime.user_id.set(identity)
    try:
        yield
    finally:
        runtime.user_id.reset(token)


@pytest.fixture
def users(tmp_path, monkeypatch):
    monkeypatch.setenv("GROCIOUS_MULTIUSER", "1")
    monkeypatch.setenv("GROCIOUS_DEMO", "0")
    monkeypatch.setenv("GROCERY_DATA", str(tmp_path))
    monkeypatch.delenv("GROCIOUS_USER_ID", raising=False)
    monkeypatch.setattr(webgui, "DEMO", False)
    monkeypatch.setitem(webgui.app.config, "SECRET_KEY", "test-session-key")
    monkeypatch.setitem(webgui.app.config, "TESTING", True)
    monkeypatch.setattr(webgui, "trumf_data", lambda: {"ok": False, "receipts": [], "offers": []})
    monkeypatch.setattr(webgui, "rema_data", lambda: {"ok": False, "receipts": [], "offers": []})
    monkeypatch.setattr(webgui, "coop_bonus", lambda: {})
    monkeypatch.setattr(webgui, "coop_offers", lambda: {"offers": []})
    result = {}
    for name in ("alice", "bob"):
        identity = accounts.create_user(name, PASSWORD)
        with as_user(identity):
            receipt = store.ingest((name.upper() + " PRIVATE SHOP\n16.10.2026\nTOTALT 42,00 NOK").encode())
            store.correct(
                receipt["rid"],
                {"store": name.upper() + " PRIVATE SHOP", "date": "2026-10-16", "amount": "42", "currency": "NOK"},
            )
            store.state(receipt["rid"], "confirmed")
            record = archive.read_receipt("inbox", receipt["rid"])
            archive.atomic_json(runtime.data_dir() / "coop_tokens.json", {"access_token": name + "-private-token"})
        result[name] = {"id": identity, "rid": receipt["rid"], "document": record["documents"][0]["filename"]}
    return result


def login(name):
    client = webgui.app.test_client()
    assert client.get("/login").status_code == 200
    with client.session_transaction() as session:
        csrf = session["csrf"]
    response = client.post("/login", data={"username": name, "password": PASSWORD, "csrf_token": csrf})
    assert response.status_code == 302
    assert client.get("/account").status_code == 200
    with client.session_transaction() as session:
        csrf = session["csrf"]
    return client, {"X-CSRF-Token": csrf}


def test_anonymous_cannot_read_private_routes(users):
    client = webgui.app.test_client()
    for path in ("/api/summary", "/api/archive/inbox", "/api/export/2026-10.json", "/api/bookkeeping"):
        assert client.get(path).status_code == 401
    assert client.get("/inbox/" + users["alice"]["rid"]).status_code == 302
    assert client.get("/login").status_code == 200
    assert client.get("/static/style.css").status_code == 200


def test_receipts_exports_and_originals_are_private(users):
    alice, _ = login("alice")
    bob, _ = login("bob")
    for client, own, other in ((alice, "alice", "bob"), (bob, "bob", "alice")):
        index = client.get("/api/archive/inbox")
        assert index.status_code == 200 and index.json["count"] == 1
        assert index.json["receipts"][0]["archive_id"] == users[own]["rid"]
        assert client.get("/archive/inbox/" + users[other]["rid"] + ".json").status_code == 404
        assert client.get("/inbox/" + users[other]["rid"]).status_code == 404
        wrong = "/archive/inbox/" + users[other]["rid"] + "/file/" + users[other]["document"]
        assert client.get(wrong).status_code == 404
        right = "/archive/inbox/" + users[own]["rid"] + "/file/" + users[own]["document"]
        assert client.get(right).status_code == 200
        exported = client.get("/api/export/2026-10.json").get_data(as_text=True)
        assert own.upper() + " PRIVATE SHOP" in exported
        assert other.upper() + " PRIVATE SHOP" not in exported
        assert "no-store" in index.headers["Cache-Control"] and "Cookie" in index.headers["Vary"]


def test_csrf_and_owner_selection_cannot_be_forged(users):
    client, csrf = login("alice")
    value = {"enabled": True, "links": [{"label": "Alice only", "url": "https://example.org/"}]}
    assert client.post("/api/navigation", json=value).status_code == 403
    assert client.post("/api/navigation", json=value, headers=csrf).status_code == 200
    forged = {**csrf, "X-User-ID": users["bob"]["id"]}
    assert (
        client.get("/api/archive/inbox?user=" + users["bob"]["id"], headers=forged).json["receipts"][0]["archive_id"]
        == users["alice"]["rid"]
    )
    with as_user(users["bob"]["id"]):
        assert navigation.load()["links"] == []
    assert (
        client.post(
            "/api/bookkeeping/inbox/" + users["bob"]["rid"], json={"registered": True}, headers=csrf
        ).status_code
        == 404
    )
    assert client.get("/").status_code == 200


def test_provider_settings_do_not_inherit_server_credentials(users, monkeypatch):
    monkeypatch.setenv("REMA_PHONE", "server-private-phone")
    alice, csrf = login("alice")
    assert alice.post("/account", data={"rema_phone": "4712345678"}, headers=csrf).status_code == 200
    with as_user(users["alice"]["id"]):
        assert runtime.setting("REMA_PHONE") == "4712345678"
    with as_user(users["bob"]["id"]):
        assert runtime.setting("REMA_PHONE") == ""
        assert json.loads((runtime.data_dir() / "coop_tokens.json").read_text())["access_token"] == "bob-private-token"


def test_logout_disabled_users_and_password_reset_revoke_sessions(users):
    alice, csrf = login("alice")
    assert alice.post("/logout", headers=csrf).status_code == 302
    assert alice.get("/api/summary").status_code == 401
    alice, _ = login("alice")
    accounts.change_password(users["alice"]["id"], "a-different-long-password")
    assert alice.get("/api/archive/inbox").status_code == 401
    bob, _ = login("bob")
    accounts.set_active(users["bob"]["id"], False)
    assert bob.get("/api/archive/inbox").status_code == 401


def test_login_rate_limit_and_no_plaintext_password(users):
    client = webgui.app.test_client()
    client.get("/login")
    with client.session_transaction() as session:
        csrf = session["csrf"]
    for _ in range(5):
        response = client.post("/login", data={"username": "alice", "password": "wrong", "csrf_token": csrf})
        assert response.status_code == 401
    assert (
        client.post("/login", data={"username": "alice", "password": PASSWORD, "csrf_token": csrf}).status_code == 429
    )
    assert PASSWORD not in accounts.find_user("alice")["password_hash"]


def test_concurrent_storage_provider_and_memory_caches_do_not_mix(users):
    barrier = threading.Barrier(2)

    @webgui._cache(300)
    def provider():
        return json.loads((runtime.data_dir() / "coop_tokens.json").read_text())["access_token"]

    @webgui._line_cache("private-test")
    def lines(rid):
        return [{"name": runtime.user_id.get()}]

    def work(name):
        with as_user(users[name]["id"]):
            barrier.wait(timeout=5)
            first = provider()
            assert str(webgui.DATA) == str(runtime.user_dir(users[name]["id"]))
            return first, lines("same-receipt-id"), provider()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(work, ("alice", "bob")))
    for name, (first, line, second) in zip(("alice", "bob"), results):
        assert first == second == name + "-private-token"
        assert line == [{"name": users[name]["id"]}]
    assert runtime.user_id.get() is None
    with pytest.raises(RuntimeError):
        runtime.data_dir()


def test_background_job_scope_and_invalid_identifiers(users, monkeypatch):
    monkeypatch.setenv("GROCIOUS_USER_ID", users["bob"]["id"])
    assert runtime.data_dir() == runtime.user_dir(users["bob"]["id"])
    with pytest.raises(ValueError):
        runtime.user_dir("../../alice")
    with pytest.raises(ValueError):
        accounts.create_user("../alice", PASSWORD)


def test_session_secret_is_persistent_and_private(users):
    first = accounts.secret_key()
    assert first == accounts.secret_key() and len(first) == 32
    assert (runtime.root_dir() / "auth" / "session.key").stat().st_mode & 0o777 == 0o600


def test_concurrent_authenticated_requests_keep_their_own_context(users, monkeypatch):
    alice, _ = login("alice")
    bob, _ = login("bob")
    barrier = threading.Barrier(2)

    @webgui._cache(300)
    def private_provider():
        barrier.wait(timeout=5)
        marker = json.loads((runtime.data_dir() / "coop_tokens.json").read_text())["access_token"]
        return {"ok": False, "err": marker, "receipts": [], "offers": []}

    monkeypatch.setattr(webgui, "trumf_data", private_provider)

    def summary(client):
        first = client.get("/api/summary").json["trumf"]["err"]
        assert client.get("/api/summary").json["trumf"]["err"] == first
        return first

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(summary, (alice, bob))) == ["alice-private-token", "bob-private-token"]
    assert runtime.user_id.get() is None


def test_worker_cli_selects_only_named_user(users, monkeypatch):
    import users as user_cli

    captured = {}

    def execute(program, arguments, environment):
        captured.update(program=program, arguments=arguments, environment=environment)

    monkeypatch.setattr(user_cli.os, "execve", execute)
    monkeypatch.setattr(user_cli.sys, "argv", ["users.py", "run", "alice", "coop_archive.py", "--incremental"])
    user_cli.main()
    assert captured["environment"]["GROCIOUS_USER_ID"] == users["alice"]["id"]
    assert captured["environment"]["GROCIOUS_MULTIUSER"] == "1"
    assert captured["environment"]["GROCIOUS_DEMO"] == "0"
    assert captured["arguments"][-1] == "--incremental"
