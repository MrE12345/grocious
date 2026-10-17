"""AGPL-3.0: owner-controlled Rema browser test with one-use PKCE return."""
import base64
import hashlib
import hmac
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit
import requests
from coop_login import LoginError
from provider_login import REMA_CALLBACK, phone_number


class BrowserAttempt:
    def __init__(self, phone):
        if not isinstance(phone,str):raise LoginError('Skriv inn mobilnummeret til Rema-kontoen.')
        self.phone=phone_number(phone)
        self.verifier=secrets.token_urlsafe(48)
        # Rema's redirect page accepts alphanumeric state only.
        self.state=secrets.token_hex(32)
        self.expires=time.time()+900

    def authorization_url(self):
        challenge=base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b'=').decode()
        return 'https://id.rema.no/authorization?'+urlencode(dict(response_type='code',client_id='android-251010',
            scope='all',redirect_uri=REMA_CALLBACK,state=self.state,code_challenge=challenge,code_challenge_method='S256'))

    def code_from_return(self, value):
        if not isinstance(value,str) or not 1<=len(value)<=8192 or any(ord(c)<32 for c in value):
            raise LoginError('Lim inn hele returadressen fra Rema-fanen.')
        try:
            parsed=urlsplit(value.strip())
            if parsed.scheme!='https' or parsed.hostname!='ae-appen.appspot.com' or parsed.port not in {None,443} or parsed.username or parsed.password or parsed.path!='/redirect/redirect.html' or parsed.fragment:
                raise ValueError()
            values=parse_qs(parsed.query,keep_blank_values=True,strict_parsing=True,max_num_fields=8)
            states=values.get('state',[])
            if len(states)!=1 or not re.fullmatch('[a-f0-9]{64}',states[0]) or not hmac.compare_digest(states[0],self.state):
                raise ValueError()
            if 'error' in values:
                raise LoginError('Rema fullførte ikke innloggingen. Start et nytt forsøk.')
            codes=values.get('code',[])
            if len(codes)!=1 or not re.fullmatch('[A-Za-z0-9._~+/=-]{1,2048}',codes[0]):raise ValueError()
            if any(k not in {'state','code','scope','session_state'} for k in values):raise ValueError()
            return codes[0]
        except (ValueError,TypeError):
            raise LoginError('Returadressen tilhører ikke dette innloggingsforsøket. Bruk adressen fra den nyeste Rema-fanen.') from None

    def exchange(self, code):
        try:
            response=requests.post('https://id.rema.no/token',data=dict(grant_type='authorization_code',client_id='android-251010',
                code=code,redirect_uri=REMA_CALLBACK,code_verifier=self.verifier),timeout=20,allow_redirects=False)
            if response.status_code!=200:
                raise LoginError('Rema kunne ikke bekrefte returadressen. Start et nytt forsøk. [REMA_BROWSER_TOKEN_REJECTED]')
            tokens=response.json()
            if not isinstance(tokens,dict) or not all(isinstance(tokens.get(k),str) and 0<len(tokens[k])<=64000 for k in ('access_token','refresh_token')):
                raise LoginError('Rema returnerte ingen varig innlogging. [REMA_BROWSER_TOKEN_FORMAT]')
            tokens['_phone']=self.phone
            return tokens
        except (requests.RequestException,ValueError):
            raise LoginError('Rema kunne ikke bekrefte innloggingen nå. Start et nytt forsøk. [REMA_BROWSER_TOKEN_NETWORK]') from None
        finally:
            code=self.verifier=self.phone=None
