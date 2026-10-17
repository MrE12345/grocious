"""Exercise the actual browser login code against a simulated Coop OAuth flow."""
import asyncio
import base64
import hashlib
import time
import unittest
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit, urlencode
from unittest.mock import patch

import coop_login


class CoopBrowserTests(unittest.TestCase):
    def test_browser_identifier_password_sms_pkce_and_state(self):self.flow(True)

    def test_callback_with_wrong_oauth_state_cannot_exchange_tokens(self):self.flow(False)

    def test_sms_page_can_submit_automatically_when_code_is_filled(self):self.flow(True, auto_submit=True)

    def test_empty_error_container_does_not_reject_login(self):self.flow(True, empty_alert=True)

    def flow(self, valid_state, auto_submit=False, empty_alert=False):
        from playwright.async_api import async_playwright as real_factory
        observations={};progress=[]
        class Harness:
            async def __aenter__(self):
                self.manager=real_factory();self.real=await self.manager.__aenter__()
                self.chromium=SimpleNamespace(launch=self.launch);return self
            async def __aexit__(self,*args):await self.manager.__aexit__(*args)
            async def launch(self,**kwargs):
                browser=await self.real.chromium.launch(**kwargs)
                original=browser.new_context
                async def context(**options):
                    result=await original(**options)
                    result.set_default_timeout(1200)
                    async def route(request_route):
                        url=urlsplit(request_route.request.url)
                        if url.path=='/authorize':
                            observations.update({k:v[0] for k,v in parse_qs(url.query).items()})
                            html='<form method="post" action="/u/password"><input name="username" id="username"><button>Fortsett</button></form>'
                        elif url.path=='/u/password':
                            html='<form method="post" action="/u/sms"><input name="password" type="password"><button>Logg inn</button></form>'
                        elif url.path=='/u/sms':
                            handler=' oninput="if(this.value.length===6)this.form.submit()"' if auto_submit else ''
                            html='<form id="sms" method="post" action="/u/finish"><input name="code" autocomplete="one-time-code"'+handler+'><button>Bekreft</button></form>'
                            if empty_alert:
                                html='<div role="alert"></div><style>#sms{display:none}</style>'+html+'<script>setTimeout(()=>document.getElementById("sms").style.display="block",900)</script>'
                        elif url.path=='/u/finish':
                            observations['sms']=parse_qs(request_route.request.post_data)['code'][0]
                            destination=coop_login.CALLBACK+'?'+urlencode({'code':'synthetic-oauth-code','state':observations['state'] if valid_state else 'wrong-state'})
                            return await request_route.fulfill(status=302,headers={'Location':destination})
                        else:raise AssertionError('Unexpected network request: '+url.path)
                        await request_route.fulfill(status=200,body=html,content_type='text/html')
                    await result.route('**/*',route)
                    async def exchange(url,**request):
                        assert url=='https://login.coop.no/oauth/token'
                        observations['exchange']=request['form']
                        async def payload():return {'access_token':'synthetic-access','refresh_token':'synthetic-refresh'}
                        return SimpleNamespace(status=200,json=payload)
                    result.request.post=exchange
                    return result
                browser.new_context=context;return browser
        with patch('playwright.async_api.async_playwright',Harness):
            if not valid_state:
                with self.assertRaises(coop_login.LoginError):
                    asyncio.run(coop_login.authenticate('synthetic-user','synthetic-password',lambda deadline:'123456',lambda s,m:progress.append(s),lambda:False))
                self.assertNotIn('exchange',observations);return
            result=asyncio.run(coop_login.authenticate('synthetic-user','synthetic-password',lambda deadline:'123456',lambda s,m:progress.append(s),lambda:False))
        self.assertEqual(result['refresh_token'],'synthetic-refresh')
        self.assertEqual(observations['sms'],'123456')
        self.assertEqual(observations['exchange']['code'],'synthetic-oauth-code')
        actual=base64.urlsafe_b64encode(hashlib.sha256(observations['exchange']['code_verifier'].encode()).digest()).rstrip(b'=').decode()
        self.assertEqual(actual,observations['code_challenge'])
        self.assertIn('awaiting_sms',progress);self.assertIn('checking_sms',progress);self.assertIn('finishing',progress)
