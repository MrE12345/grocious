"""Direct browser returns are one-use, private and bound to the initiating profile."""
import base64
import hashlib
import json
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs,urlsplit,urlencode
import service
import vault
import browser_login
import test_service as fixtures


class BrowserLoginTests(unittest.TestCase):
    setUp=fixtures.CollectorTests.setUp
    tearDown=fixtures.CollectorTests.tearDown
    auth=fixtures.CollectorTests.auth

    def start(self,profile=None,generation=None):
        profile=profile or self.first;self.owner=self.app.collectors['rema']
        result=self.client.post('/v1/profiles/'+profile+'/providers/rema/browser-start',headers=self.auth(profile),json={'username':'91234567','privacy_generation':generation})
        self.assertEqual(result.status_code,202,result.json)
        attempt=result.json['attempt'];query=parse_qs(urlsplit(result.json['authorization_url']).query)
        return attempt,query

    def url(self,query,**changes):
        values={'code':'synthetic-code','state':query['state'][0],**changes}
        return browser_login.REMA_CALLBACK+'?'+urlencode(values)

    def complete(self,attempt,url,profile=None):
        profile=profile or self.first
        return self.client.post('/v1/profiles/'+profile+'/providers/rema/browser-complete',headers=self.auth(profile),json={'attempt':attempt,'return_url':url})

    def test_start_uses_alphanumeric_state_and_keeps_pkce_phone_in_memory(self):
        attempt,query=self.start();pending=self.owner.browser_attempts[attempt]
        self.assertRegex(query['state'][0],'^[a-f0-9]{64}$')
        expected=base64.urlsafe_b64encode(hashlib.sha256(pending.verifier.encode()).digest()).rstrip(b'=').decode()
        self.assertEqual(query['code_challenge'],[expected]);self.assertEqual(query['redirect_uri'],[browser_login.REMA_CALLBACK])
        self.assertTrue(self.owner.status(self.first)['login']['browser'])
        self.assertFalse(self.owner.codes)
        for path in Path(self.temp.name).rglob('*'):
            if path.is_file():
                for value in [pending.phone,pending.verifier,pending.state]:self.assertNotIn(value.encode(),path.read_bytes())

    def test_owner_return_exchanges_once_and_reuses_private_account_binding(self):
        attempt,query=self.start();pending=self.owner.browser_attempts[attempt];verifier=pending.verifier
        with patch('browser_login.requests.post',return_value=SimpleNamespace(status_code=200,json=lambda:fixtures.tokens('one'))) as exchange,patch.object(self.owner,'schedule_sync') as sync:
            result=self.complete(attempt,self.url(query));self.assertEqual(result.status_code,202)
            self.assertEqual(exchange.call_count,1);args=exchange.call_args
            self.assertEqual(args.args[0],'https://id.rema.no/token');self.assertFalse(args.kwargs['allow_redirects'])
            self.assertEqual(args.kwargs['data']['code_verifier'],verifier)
            self.assertEqual(self.complete(attempt,self.url(query)).status_code,409)
            self.assertEqual(exchange.call_count,1);sync.assert_called_once_with(self.first)
        self.assertTrue(self.owner.status(self.first)['connected'])
        stored=vault.load(self.owner.folder(self.first)/'vault.enc',self.first,'rema')
        self.assertEqual(stored['tokens']['_phone'],'91234567')
        self.assertFalse(self.owner.browser_attempts)
        second,other=self.start(self.second)
        with patch('browser_login.requests.post',return_value=SimpleNamespace(status_code=200,json=lambda:fixtures.tokens('one'))),patch.object(self.owner,'schedule_sync') as sync:
            self.complete(second,self.url(other),self.second);sync.assert_not_called()
        self.assertFalse(self.owner.status(self.second)['connected'])
        self.assertIn('annen bruker',self.owner.status(self.second)['login']['message'])

    def test_other_profile_invalid_state_duplicate_code_and_other_origins_never_exchange(self):
        attempt,query=self.start()
        with patch('browser_login.requests.post') as exchange:
            self.assertEqual(self.complete(attempt,self.url(query),self.second).status_code,404)
            bad=[self.url(query,state='f'*64),self.url(query)+'&code=duplicate',self.url(query).replace('https://ae-appen.appspot.com/','https://ae-appen.appspot.com.evil.test/'),self.url(query).replace('https://','http://'),self.url(query)+'#fragment','https://ae-appen.appspot.com/redirect/redirect.html?code=only']
            for value in bad:self.assertEqual(self.complete(attempt,value).status_code,400)
            exchange.assert_not_called()
        self.assertIn(attempt,self.owner.browser_attempts)

    def test_cancel_expiry_and_erasure_remove_pending_browser_material(self):
        attempt,query=self.start();self.owner.cancel(self.first)
        self.assertNotIn(attempt,self.owner.browser_attempts)
        with patch('browser_login.requests.post') as exchange:
            self.assertEqual(self.complete(attempt,self.url(query)).status_code,409);exchange.assert_not_called()
        attempt,query=self.start();self.owner.browser_attempts[attempt].expires=0
        self.assertEqual(self.owner.status(self.first)['login']['state'],'failed');self.assertFalse(self.owner.browser_attempts)
        attempt,query=self.start();self.owner.purge(self.first,'f'*48)
        self.assertFalse(self.owner.browser_attempts)
        result=self.client.post('/v1/profiles/'+self.first+'/providers/rema/browser-start',headers=self.auth(self.first),json={'username':'91234567'})
        self.assertEqual(result.status_code,409)

    def test_failed_token_exchange_has_no_raw_secrets_and_cannot_be_replayed(self):
        attempt,query=self.start()
        with patch('browser_login.requests.post',side_effect=browser_login.requests.RequestException('private-code-and-verifier')) as exchange:
            result=self.complete(attempt,self.url(query));self.assertEqual(result.status_code,202)
            status=self.owner.status(self.first);self.assertFalse(status['connected'])
            self.assertIn('REMA_BROWSER_TOKEN_NETWORK',status['login']['message'])
            self.assertNotIn('private-code-and-verifier',json.dumps(status))
            self.assertEqual(self.complete(attempt,self.url(query)).status_code,409);self.assertEqual(exchange.call_count,1)

    def test_provider_callback_error_and_missing_phone_are_safe(self):
        result=self.client.post('/v1/profiles/'+self.first+'/providers/rema/browser-start',headers=self.auth(self.first),json={})
        self.assertEqual(result.status_code,400)
        attempt,query=self.start()
        with patch('browser_login.requests.post') as exchange:
            result=self.complete(attempt,self.url(query,error='access_denied',error_description='private-provider-details'))
            self.assertEqual(result.status_code,400);self.assertNotIn(b'private-provider-details',result.data);exchange.assert_not_called()
