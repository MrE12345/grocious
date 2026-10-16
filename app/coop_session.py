"""Coop API session headers shared by receipts, coupons and benefits."""

import runtime
import json
import os
import uuid
from pathlib import Path

import receipt_archive as archive


def load_headers(data=None):
    data = Path(data) if data is not None else runtime.data_dir()
    session = data / "coop_session.json"
    tokens = data / "coop_tokens.json"
    if not session.exists() and not tokens.exists():
        raise FileNotFoundError("Coop login unavailable")
    saved = json.loads(session.read_text()).get("headers", {}) if session.exists() else {}
    headers = {
        key.lower(): value for key, value in saved.items()
        if key.lower() not in ("host", "accept-encoding", "content-length")
    }
    if tokens.exists():
        token = json.loads(tokens.read_text()).get("access_token")
        if token:
            headers["x-token"] = token
    version = os.environ.get("COOP_APP_VERSION", "4.31.0")
    build = os.environ.get("COOP_APP_BUILD", "6871")
    android = os.environ.get("COOP_ANDROID_VERSION", "15")
    headers.setdefault("user-agent", f"Android({android})/Coop({version}/{build})")
    headers.setdefault("x-deviceid", str(uuid.uuid4()))
    headers.setdefault("x-locale", "nb_NO")
    headers.setdefault("accept", "application/json")
    if headers != saved:
        archive.atomic_json(session, {"headers": headers})
    return headers
