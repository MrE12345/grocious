"""AGPL-3.0: credentials for one provider job, supplied in its private tmpfs."""
import json
import os
import uuid
from pathlib import Path
import requests
import vault


def rema_headers():
    root = Path(os.environ['GROCERY_DATA'])
    tokens = json.loads((root/'rema_tokens.json').read_text())
    response = requests.post('https://id.rema.no/token', data={'grant_type':'refresh_token',
        'client_id':'android-251010','refresh_token':tokens['refresh_token']}, timeout=30)
    response.raise_for_status(); updated = response.json()
    updated.setdefault('refresh_token', tokens['refresh_token']); updated['_phone'] = tokens['_phone']
    vault.checkpoint(updated)
    vault.atomic(root/'rema_tokens.json', json.dumps(updated).encode())
    device = json.loads((root/'rema_device.json').read_text())['device_id']
    return {'Authorization':'Bearer '+updated['access_token'],'ocp-apim-subscription-key':'fb5e24884b504d0bad761098f77e6605',
        'x-platform':'android','x-correlation-id':str(uuid.uuid4()),'x-device-id':device,
        'x-mobile-nr':updated['_phone'],'x-app':'bella','x-app-version':'3.0.12 #110549','Accept':'application/json'}


def trumf_session():
    root = Path(os.environ['GROCERY_DATA'])
    tokens = json.loads((root/'trumf_tokens.json').read_text())
    state = tokens['storage_state']; session = requests.Session()
    session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0 Safari/537.36'
    for cookie in state.get('cookies', []):
        domain = cookie.get('domain', '').lstrip('.')
        if domain == 'trumf.no' or domain.endswith('.trumf.no'):
            session.cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'], path=cookie.get('path','/'), secure=True)
    response = session.get('https://www.trumf.no/api/auth/session', timeout=30)
    response.raise_for_status(); token = response.json().get('accessToken')
    if not token: raise ValueError('Trumf session expired')
    tokens['access_token'] = token
    tokens['storage_state'] = {'cookies':[{'name':c.name,'value':c.value,'domain':c.domain,'path':c.path,
        'expires':c.expires if c.expires is not None else -1,'httpOnly':True,'secure':True,'sameSite':'Lax'} for c in session.cookies], 'origins':[]}
    vault.checkpoint(tokens)
    return session
