"""Run the provider login implementation in Chromium with synthetic supplier pages."""
import asyncio
import base64
import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit
import provider_login as login
from coop_login import LoginError


class BrowserTests(unittest.TestCase):
    def test_rema_sms_and_pkce(self): self.flow('rema')
    def test_rema_wrong_state_never_exchanges_code(self): self.flow('rema', False)
    def test_trumf_password_sms_and_private_cookie_state(self): self.flow('trumf')

    def test_trusted_hosts_and_mobile_validation(self):
        self.assertEqual(login.phone_number('+47 912 34 567'),'91234567')
        for value in ['https://id.rema.no.evil.test/','https://id.rema.no@evil.test/','http://id.rema.no/','https://id.rema.no:8443/']:
            self.assertFalse(login.trusted(value,{'id.rema.no'}))
        for value in ['123','abcdefghi','../private']:
            with self.assertRaises(LoginError):login.phone_number(value)

    def test_rema_owner_can_complete_manual_verification_then_receive_sms(self): self.flow('rema', challenge=True)

    def test_rema_sms_can_submit_automatically(self):self.flow('rema',auto_submit=True)

    def flow(self, provider, valid_state=True, challenge=False, auto_submit=False):
        from playwright.async_api import async_playwright as real_factory
        observations={}; states=[]
        class Harness:
            async def __aenter__(self):
                self.manager=real_factory(); self.real=await self.manager.__aenter__()
                self.chromium=SimpleNamespace(launch=self.launch); return self
            async def __aexit__(self,*args): await self.manager.__aexit__(*args)
            async def launch(self,**kwargs):
                browser=await self.real.chromium.launch(**kwargs); original=browser.new_context
                async def context(**options):
                    ctx=await original(**options)
                    async def route(r):
                        u=urlsplit(r.request.url)
                        if u.path=='/authorization':
                            observations.update({k:v[0] for k,v in parse_qs(u.query).items()})
                            html='<form method="post" action="/sms"><input type="tel" name="phoneNumber"><button>Send meg engangskode</button></form>'
                        elif u.path=='/login':
                            html='<form method="post" action="/password"><input type="tel" name="username"><button>Neste</button></form>'
                        elif u.path=='/password':
                            observations['username']=parse_qs(r.request.post_data)['username'][0]
                            html='<form method="post" action="/sms"><input type="password" name="password"><button>Logg inn</button></form>'
                        elif u.path=='/recaptcha/api2/bframe':
                            html='<button style="position:absolute;left:30px;top:30px;width:120px;height:70px" onclick="parent.location.href=\'/verified-sms\'">Testbekreftelse</button>'
                        elif u.path in {'/sms','/verified-sms'}:
                            observations['first_form']=parse_qs(r.request.post_data or '')
                            handler=' oninput="if(this.value.length===6)this.form.submit()"' if auto_submit else ''
                            html='<form method="post" action="/finish"><input name="code" autocomplete="one-time-code"'+handler+'><button>Bekreft</button></form>'
                            if challenge and u.path=='/sms':html='<iframe src="/recaptcha/api2/bframe" style="width:360px;height:200px;border:0"></iframe>'
                        elif u.path=='/finish':
                            observations['sms']=parse_qs(r.request.post_data)['code'][0]
                            if provider=='rema':
                                destination=login.REMA_CALLBACK+'?'+urlencode({'code':'synthetic-code','state':observations['state'] if valid_state else 'wrong'})
                            else: destination='https://www.trumf.no/'
                            observations['complete']=True
                            return await r.fulfill(status=200,body='<script>location.href='+__import__('json').dumps(destination)+'</script>',content_type='text/html')
                        elif u.hostname=='www.trumf.no' and u.path=='/':
                            await ctx.add_cookies([{'name':'synthetic-session','value':'private-cookie','url':'https://www.trumf.no/','secure':True,'httpOnly':True}])
                            html='Logget inn'
                        else: raise AssertionError('Unexpected browser request '+u.path)
                        await r.fulfill(status=200,body=html,content_type='text/html')
                    await ctx.route('**/*',route)
                    async def get(url,**kwargs):
                        async def data():
                            if url.endswith('/csrf'):return {'csrfToken':'synthetic-csrf'}
                            return {'accessToken':'synthetic-access'} if observations.get('complete') else {}
                        return SimpleNamespace(status=200,json=data)
                    async def post(url,**kwargs):
                        if provider=='trumf':
                            self_outer.assertEqual(kwargs['form']['csrfToken'],'synthetic-csrf')
                            return SimpleNamespace(status=200,url='https://id.trumf.no/login',headers={'content-type':'text/html'})
                        self_outer.assertEqual(url,'https://id.rema.no/token')
                        observations['exchange']=kwargs['form']
                        async def data():return {'access_token':'synthetic-access','refresh_token':'synthetic-refresh'}
                        return SimpleNamespace(status=200,json=data)
                    ctx.request.get=get;ctx.request.post=post
                    return ctx
                browser.new_context=context;return browser
        self_outer=self
        original_trusted=login.trusted
        def tracked(url,hosts):
            observations.setdefault('pages',[]).append(url)
            return original_trusted(url,hosts)
        pending_clicks=[]
        def progress(state,message):
            states.append(state)
            if state=='verification':
                self.assertTrue(message['image'].startswith(b'\x89PNG'))
                pending_clicks.append({'x':60,'y':60,'geometry':message['geometry']})
            if state=='verification_poll' and pending_clicks:return pending_clicks.pop(0)
        with patch('playwright.async_api.async_playwright',Harness),patch.object(login,'trusted',side_effect=tracked):
            coroutine=getattr(login,provider)('91234567','synthetic-password',lambda deadline:'123456',progress,lambda:False)
            if not valid_state:
                with self.assertRaises(LoginError):asyncio.run(coroutine)
                self.assertNotIn('exchange',observations);return
            try:result=asyncio.run(coroutine)
            except Exception as exc:raise AssertionError(str(observations)) from exc
        self.assertEqual(result['access_token'],'synthetic-access')
        self.assertEqual(observations['sms'],'123456')
        self.assertIn('awaiting_sms',states);self.assertIn('finishing',states)
        if provider=='rema':
            actual=base64.urlsafe_b64encode(hashlib.sha256(observations['exchange']['code_verifier'].encode()).digest()).rstrip(b'=').decode()
            self.assertEqual(actual,observations['code_challenge']);self.assertEqual(result['_phone'],'91234567')
            if challenge:self.assertIn('verification',states)
        else:
            self.assertEqual(observations['first_form']['password'],['synthetic-password'])
            self.assertEqual(result['storage_state']['cookies'][0]['value'],'private-cookie')
