"""AGPL-3.0: encrypted profile credentials; plaintext exists only in job tmpfs."""
import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path
from cryptography.fernet import Fernet


def secret():
    value = Path(os.environ['GROCIOUS_SERVICE_KEY_FILE']).read_bytes().strip()
    if len(value) < 32:
        raise RuntimeError('Service key is too short')
    return value


def atomic(path, body):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def account(tokens, provider="coop"):
    token = tokens.get('access_token', '')
    payload = token.split('.')[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    subject = claims.get('sub')
    if not isinstance(subject, str) or not subject or len(subject) > 1000:
        raise ValueError('Missing account identity')
    identity = subject if provider == 'coop' else provider + '\0' + subject
    return hashlib.sha256(identity.encode()).hexdigest()


def cipher(profile, provider="coop"):
    identity = profile if provider == 'coop' else provider + '\0' + profile
    key = hashlib.sha256(secret() + b'\0vault\0' + identity.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def save(path, profile, value, expected_account):
    if account(value['tokens'], value.get('provider', 'coop')) != expected_account:
        raise ValueError('Different account; separate archive required')
    atomic(path, cipher(profile, value.get('provider', 'coop')).encrypt(json.dumps(value).encode()))


def load(path, profile, provider="coop"):
    return json.loads(cipher(profile, provider).decrypt(Path(path).read_bytes()))


def checkpoint(tokens):
    path = os.environ.get('GROCIOUS_PROFILE_VAULT')
    if path:
        profile = os.environ['GROCIOUS_PROFILE_ID']
        value = load(path, profile, os.environ.get('GROCIOUS_PROVIDER','coop')); value['tokens'] = tokens
        save(path, profile, value, os.environ['GROCIOUS_EXPECTED_ACCOUNT'])
