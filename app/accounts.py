"""Local accounts and revocable sessions. Administrators create users using users.py."""

from contextlib import contextmanager
from datetime import timedelta
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
import uuid

from flask import abort, g, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import runtime

DUMMY_HASH = generate_password_hash("grocious-unused-constant-password")


@contextmanager
def database():
    directory = runtime.root_dir() / "auth"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "accounts.sqlite3"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)
    connection = sqlite3.connect(path, timeout=15)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
                session_version INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS attempts (key TEXT NOT NULL, created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS attempts_key_time ON attempts(key, created);
        """)
        yield connection
        connection.commit()
    finally:
        connection.close()


def normalize(username):
    value = username.strip().casefold()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.@+\-]{2,79}", value):
        raise ValueError("Bruk 3–80 tegn: bokstaver a–z, tall eller . _ @ + -")
    return value


def validate_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValueError("Passordet må ha mellom 12 og 1024 tegn.")


def create_user(username, password):
    username = normalize(username)
    validate_password(password)
    identity = uuid.uuid4().hex
    password_hash = generate_password_hash(password)
    with database() as db:
        db.execute(
            "INSERT INTO users(id, username, password_hash) VALUES (?, ?, ?)", (identity, username, password_hash)
        )
    directory = runtime.user_dir(identity)
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.mkdir(mode=0o700)
    return identity


def get_user(identity):
    with database() as db:
        row = db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (identity,)).fetchone()
        return dict(row) if row else None


def find_user(username):
    with database() as db:
        row = db.execute("SELECT * FROM users WHERE username = ?", (normalize(username),)).fetchone()
        return dict(row) if row else None


def change_password(identity, password):
    validate_password(password)
    hashed = generate_password_hash(password)
    with database() as db:
        db.execute(
            "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?", (hashed, identity)
        )


def set_active(identity, active):
    with database() as db:
        db.execute(
            "UPDATE users SET active = ?, session_version = session_version + 1 WHERE id = ?", (int(active), identity)
        )


def authenticate(username, password, address):
    try:
        username = normalize(username)
    except (ValueError, AttributeError):
        username = "invalid"
    pair = hashlib.sha256((address + "\0" + username).encode()).hexdigest()
    peer = hashlib.sha256(("ip\0" + address).encode()).hexdigest()
    now = time.time()
    with database() as db:
        db.execute("DELETE FROM attempts WHERE created < ?", (now - 900,))
        for key, maximum in ((pair, 5), (peer, 30)):
            if db.execute("SELECT COUNT(*) FROM attempts WHERE key = ?", (key,)).fetchone()[0] >= maximum:
                return None, True
        db.executemany("INSERT INTO attempts VALUES (?, ?)", ((pair, now), (peer, now)))
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        valid = check_password_hash(row["password_hash"] if row else DUMMY_HASH, password)
        if row and row["active"] and valid:
            db.execute("DELETE FROM attempts WHERE key = ?", (pair,))
            return dict(row), False
    return None, False


def secret_key():
    directory = runtime.root_dir() / "auth"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "session.key"
    if not path.exists():
        fd, temporary = tempfile.mkstemp(dir=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary)
    return path.read_bytes()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    if (
        not isinstance(supplied, str)
        or not supplied.isascii()
        or not supplied
        or not hmac.compare_digest(session.get("csrf", ""), supplied)
    ):
        abort(403, "Last siden på nytt før du sender skjemaet.")


def install(app):
    app.config.update(
        SESSION_COOKIE_NAME="grocious_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    )
    if runtime.multiuser():
        if os.environ.get("GROCIOUS_DEMO", "0").lower() not in ("", "0", "false"):
            raise RuntimeError("Multi-user mode cannot share demo fixtures")
        app.secret_key = secret_key()
        app.config["SESSION_COOKIE_SECURE"] = os.environ.get("GROCIOUS_COOKIE_SECURE", "0") == "1"

    @app.before_request
    def authenticate_request():
        g.account = None
        if not runtime.multiuser():
            return None
        if request.endpoint == "static" or request.path in (
            "/login",
            "/themes.css",
            "/favicon.ico",
            "/manifest.webmanifest",
            "/sw.js",
        ):
            return None
        account = get_user(session.get("uid", ""))
        if not account or account["session_version"] != session.get("version"):
            session.clear()
            if request.path.startswith("/api/") or request.is_json:
                return jsonify(error="Innlogging kreves."), 401
            return redirect("/login")
        g.account = account
        g.storage_token = runtime.user_id.set(account["id"])
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            check_csrf()
        return None

    @app.teardown_request
    def release_user(error):
        token = g.pop("storage_token", None)
        if token is not None:
            runtime.user_id.reset(token)

    @app.after_request
    def private_response(response):
        if runtime.multiuser() and request.endpoint != "static":
            response.headers["Cache-Control"] = "private, no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.vary.add("Cookie")
        return response

    @app.context_processor
    def account_context():
        return {
            "account": g.get("account"),
            "multiuser": runtime.multiuser(),
            "csrf_token": csrf_token() if runtime.multiuser() else "",
        }

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not runtime.multiuser():
            return redirect("/")
        error = None
        status = 200
        if request.method == "POST":
            if request.content_length and request.content_length > 16384:
                abort(413)
            check_csrf()
            password = request.form.get("password", "")
            if len(password) > 1024:
                abort(400)
            account, throttled = authenticate(request.form.get("username", ""), password, request.remote_addr or "")
            if account:
                session.clear()
                session.update(uid=account["id"], version=account["session_version"], permanent=True)
                return redirect("/")
            error = "For mange forsøk. Vent 15 minutter." if throttled else "Feil brukernavn eller passord."
            status = 429 if throttled else 401
        return render_template("login.html", error=error, csrf_token=csrf_token()), status

    @app.post("/logout")
    def logout():
        if not runtime.multiuser():
            return redirect("/")
        session.clear()
        return redirect("/login" if runtime.multiuser() else "/")

    @app.route("/account", methods=["GET", "POST"])
    def profile():
        if not runtime.multiuser():
            return redirect("/")
        from receipt_archive import atomic_json

        path = runtime.data_dir() / "settings.json"
        error = None
        saved = False
        if request.method == "POST":
            phone = request.form.get("rema_phone", "").strip()
            if phone and not re.fullmatch(r"\+?\d{8,15}", phone):
                error = "Skriv et gyldig telefonnummer."
            else:
                settings = json.loads(path.read_text()) if path.exists() else {}
                settings["REMA_PHONE"] = phone
                atomic_json(path, settings)
                saved = True
        return render_template("account.html", rema_phone=runtime.setting("REMA_PHONE"), saved=saved, error=error)
