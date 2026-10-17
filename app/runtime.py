"""Request-local storage selection; never mutate process environment for a web user."""

from contextvars import ContextVar
import json
import os
from pathlib import Path
import re

user_id = ContextVar("grocious_user_id", default=None)


def multiuser():
    return os.environ.get("GROCIOUS_MULTIUSER", "0").lower() in ("1", "true", "yes")


def root_dir():
    return Path(os.environ.get("GROCERY_DATA", "/data"))


def user_dir(identity):
    if not isinstance(identity, str) or not re.fullmatch(r"[a-f0-9]{32}", identity):
        raise ValueError("Invalid internal user ID")
    return root_dir() / "users" / identity / "data"


def data_dir():
    if not multiuser():
        return root_dir()
    identity = user_id.get() or os.environ.get("GROCIOUS_USER_ID")
    if not identity:
        raise RuntimeError("Select an authenticated user before accessing private data")
    return user_dir(identity)


def setting(name, default=""):
    if not multiuser():
        return os.environ.get(name, default)
    try:
        return json.loads((data_dir() / "settings.json").read_text()).get(name, default)
    except (FileNotFoundError, ValueError):
        return default
