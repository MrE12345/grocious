import asyncio
import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import service
import vault


def tokens(subject):
    payload=base64.urlsafe_b64encode(json.dumps({'sub':subject}).encode()).rstrip(b'=').decode()
    return {'access_token':'header.'+payload+'.signature','refresh_token':'synthetic-refresh-'+subject}


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.key=Path(self.temp.name)/'key'; self.key.write_bytes(b'k'*64)
        self.env=patch.dict(os.environ,{'GROCIOUS_SERVICE_KEY_FILE':str(self.key)});self.env.start()
        self.collector=service.Collector(Path(self.temp.name)/'data')
        self.app=service.create_app(self.collector);self.client=self.app.test_client()
        self.first='a'*64;self.second='b'*64

    def tearDown(self):
        for instance in self.app.collectors.values():
            instance.executor.shutdown(wait=True,cancel_futures=True)
            instance.sync_executor.shutdown(wait=True,cancel_futures=True)
        self.env.stop();self.temp.cleanup()

    def auth(self,profile):
        return {'Authorization':'Bearer '+hmac.new(b'k'*64,b'profile:'+profile.encode(),hashlib.sha256).hexdigest()}

    def wait_state(self,profile,expected):
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            result=self.collector.status(profile)
            if result['login'] and result['login']['state'] in expected:return result
            time.sleep(.01)
        self.fail(str(self.collector.status(profile)))

    def test_profile_bearer_cannot_access_other_profile_or_archive(self):
        self.assertEqual(self.client.get('/v1/profiles/'+self.first+'/status').status_code,401)
        self.assertEqual(self.client.get('/v1/profiles/'+self.second+'/status',headers=self.auth(self.first)).status_code,401)
        for path in ['archive/coop/'+('f'*64)+'.json','archive/coop/'+('f'*64)+'/file/original.pdf']:
            self.assertEqual(self.client.get('/v1/profiles/'+self.second+'/'+path,headers=self.auth(self.first)).status_code,401)
        self.assertEqual(self.client.get('/v1/profiles/'+self.first+'/status',headers=self.auth(self.first)).status_code,200)
        self.assertEqual(self.client.get('/v1/profiles/../../etc/passwd',headers=self.auth(self.first)).status_code,404)

    def test_login_sms_are_scoped_and_credentials_are_not_persisted(self):
        async def login(username,password,receive,progress,cancelled):
            self.assertEqual((username,password),('synthetic-user','never-store-this-password'))
            progress('awaiting_sms','SMS')
            code=await asyncio.to_thread(receive,time.monotonic()+3)
            self.assertEqual(code,'123456');return tokens('account-one')
        self.collector.login_runner=login
        with patch.object(self.collector,'schedule_sync'):
            reply=self.client.post('/v1/profiles/'+self.first+'/login',headers=self.auth(self.first),json={'username':'synthetic-user','password':'never-store-this-password'})
            self.assertEqual(reply.status_code,202);attempt=reply.json['attempt']
            self.wait_state(self.first,{'awaiting_sms'})
            reply=self.client.post('/v1/profiles/'+self.second+'/sms',headers=self.auth(self.second),json={'attempt':attempt,'code':'123456'})
            self.assertEqual(reply.status_code,404)
            reply=self.client.post('/v1/profiles/'+self.first+'/sms',headers=self.auth(self.first),json={'attempt':attempt,'code':'123456'})
            self.assertEqual(reply.status_code,202)
            result=self.wait_state(self.first,{'connected'})
        self.assertTrue(result['connected'])
        path=self.collector.folder(self.first)/'vault.enc'
        self.assertEqual(vault.load(path,self.first)['tokens'],tokens('account-one'))
        with self.assertRaises(Exception):vault.load(path,self.second)
        for path in Path(self.temp.name).rglob('*'):
            if path.is_file():
                body=path.read_bytes()
                for secret in [b'never-store-this-password',b'123456',b'synthetic-refresh-account-one']:
                    self.assertNotIn(secret,body)

    def test_same_account_cannot_bind_other_user_and_existing_profile_cannot_switch(self):
        subject=['one']
        async def login(*args):return tokens(subject[0])
        self.collector.login_runner=login
        with patch.object(self.collector,'schedule_sync'):
            self.collector.start(self.first,'u','p');self.wait_state(self.first,{'connected'})
            self.collector.start(self.second,'u','p');result=self.wait_state(self.second,{'failed'})
            self.assertIn('annen bruker',result['login']['message']);self.assertFalse(result['connected'])
            subject[0]='two';self.collector.start(self.first,'u','p')
            result=self.wait_state(self.first,{'failed'})
            self.assertIn('annen Coop-konto',result['login']['message'])
            self.assertEqual(vault.load(self.collector.folder(self.first)/'vault.enc',self.first)['tokens'],tokens('one'))

    def test_cancel_and_restart_expire_sms_without_creating_tokens(self):
        async def login(username,password,receive,progress,cancelled):
            progress('awaiting_sms','SMS')
            await asyncio.to_thread(receive,time.monotonic()+2)
            if cancelled():raise service.coop_login.LoginError('Cancelled')
            return tokens('one')
        self.collector.login_runner=login
        attempt=self.collector.start(self.first,'u','p');self.wait_state(self.first,{'awaiting_sms'})
        self.collector.cancel(self.first)
        with self.assertRaises(service.ServiceError):self.collector.sms(self.first,attempt,'123456')
        time.sleep(.05)
        self.assertFalse((self.collector.folder(self.first)/'vault.enc').exists())

    def test_originals_with_identical_receipt_id_stay_separate(self):
        identity='e'*64
        for profile,content in [(self.first,b'first-original'),(self.second,b'second-original')]:
            folder=self.collector.folder(profile)/'receipts'/'coop'/identity
            folder.mkdir(parents=True)
            (folder/'original.pdf').write_bytes(content)
            (folder/'receipt.json').write_text(json.dumps({'id':profile,'documents':[{'filename':'original.pdf','mimetype':'application/pdf','sha256':hashlib.sha256(content).hexdigest()}]}))
        for profile,expected in [(self.first,b'first-original'),(self.second,b'second-original')]:
            reply=self.client.get('/v1/profiles/'+profile+'/archive/coop/'+identity+'/file/original.pdf',headers=self.auth(profile))
            self.assertEqual(reply.status_code,200);self.assertEqual(reply.data,expected);reply.close()
        (self.collector.folder(self.first)/'receipts'/'coop'/identity/'original.pdf').write_bytes(b'changed')
        self.assertEqual(self.client.get('/v1/profiles/'+self.first+'/archive/coop/'+identity+'/file/original.pdf',headers=self.auth(self.first)).status_code,409)

    def test_token_rotation_checkpoint_and_account_guard(self):
        path=self.collector.folder(self.first)/'vault.enc';fingerprint=vault.account(tokens('one'))
        vault.save(path,self.first,{'tokens':tokens('one')},fingerprint)
        with patch.dict(os.environ,{'GROCIOUS_PROFILE_VAULT':str(path),'GROCIOUS_PROFILE_ID':self.first,'GROCIOUS_EXPECTED_ACCOUNT':fingerprint}):
            updated={**tokens('one'),'refresh_token':'rotated'};vault.checkpoint(updated)
            self.assertEqual(vault.load(path,self.first)['tokens']['refresh_token'],'rotated')
            with self.assertRaises(ValueError):vault.checkpoint(tokens('two'))
        self.assertEqual(vault.load(path,self.first)['tokens']['refresh_token'],'rotated')

    def test_logout_removes_tokens_but_keeps_archive(self):
        async def login(*args):return tokens('one')
        self.collector.login_runner=login
        with patch.object(self.collector,'schedule_sync'):
            self.collector.start(self.first,'u','p');self.wait_state(self.first,{'connected'})
        folder=self.collector.folder(self.first);archive=folder/'receipts';archive.mkdir();(archive/'keep').write_text('receipt')
        self.collector.logout(self.first)
        self.assertFalse(self.collector.status(self.first)['connected'])
        self.assertTrue((archive/'keep').exists());self.assertFalse((folder/'vault.enc').exists())

    def test_legacy_account_reservation_blocks_wrong_user_before_archiving(self):
        fingerprint=vault.account(tokens('existing-account'))
        self.collector.reserve(self.first,hashlib.sha256(fingerprint.encode()).hexdigest())
        async def login(*args):return tokens('existing-account')
        self.collector.login_runner=login
        with patch.object(self.collector,'schedule_sync') as sync:
            self.collector.start(self.second,'u','p');self.wait_state(self.second,{'failed'})
            sync.assert_not_called()
            self.assertFalse((self.collector.folder(self.second)/'vault.enc').exists())
            self.collector.start(self.first,'u','p');self.wait_state(self.first,{'connected'})
            sync.assert_called_once_with(self.first)

    def test_collection_uses_separate_process_data_directories_and_cleans_plaintext(self):
        from types import SimpleNamespace
        captured=[]
        async def login(username,*args):return tokens(username)
        self.collector.login_runner=login
        with patch.object(self.collector,'schedule_sync'):
            self.collector.start(self.first,'one','p');self.wait_state(self.first,{'connected'})
            self.collector.start(self.second,'two','p');self.wait_state(self.second,{'connected'})
        def run(command,**kwargs):
            env=kwargs['env'];work=Path(env['GROCERY_DATA'])
            captured.append((env['GROCIOUS_PROFILE_ID'],work,(work/'receipts').resolve(),json.loads((work/'coop_tokens.json').read_text())))
            return SimpleNamespace(returncode=0)
        with patch('service.subprocess.run',side_effect=run):
            self.collector.schedule_sync(self.first);self.collector.schedule_sync(self.second)
            deadline=time.monotonic()+3
            while self.collector.active_sync and time.monotonic()<deadline:time.sleep(.01)
        self.assertEqual(len(captured),2)
        for profile,work,archive,value in captured:
            self.assertEqual(archive,self.collector.folder(profile)/'receipts')
            self.assertEqual(vault.account(value),vault.account(tokens('one' if profile==self.first else 'two')))
            self.assertFalse(work.exists())
        self.assertNotEqual(captured[0][1],captured[1][1])

    def test_credentials_and_code_validation_rate_limit_and_untrusted_page(self):
        with self.assertRaises(service.ServiceError):self.collector.start(self.first,'','p')
        with self.assertRaises(service.ServiceError):self.collector.sms(self.first,'anything','bad')
        self.assertTrue(service.coop_login.trusted_page('https://login.coop.no/u/login'))
        for url in ['http://login.coop.no/','https://login.coop.no.evil.test/','https://login.coop.no@evil.test/']:
            self.assertFalse(service.coop_login.trusted_page(url))
        with self.collector.db() as conn:
            for index in range(4):conn.execute('INSERT INTO attempts(id,profile,state,message,created,expires) VALUES(?,?,?,?,?,?)',(str(index),self.first,'failed','',time.time(),time.time()+60))
        with self.assertRaises(service.ServiceError) as error:self.collector.start(self.first,'u','p')
        self.assertEqual(error.exception.status,429)


class ProviderCollectorTests(unittest.TestCase):
    setUp=CollectorTests.setUp
    tearDown=CollectorTests.tearDown
    auth=CollectorTests.auth
    def test_three_connections_same_user_keep_tokens_archives_and_sms_separate(self):
        async def login(username,password,receive,progress,cancelled):
            progress('awaiting_sms','SMS')
            code=await asyncio.to_thread(receive,time.monotonic()+3)
            if code!='123456': raise service.coop_login.LoginError('Invalid synthetic code')
            return tokens('same-subject')
        attempts={}
        with patch.object(service.Collector,'schedule_sync'):
            for provider,instance in self.app.collectors.items():
                instance.login_runner=login
                path='providers/'+provider+'/'
                reply=self.client.post('/v1/profiles/'+self.first+'/'+path+'login',headers=self.auth(self.first),json={'username':'u','password':'' if provider=='rema' else 'p'})
                self.assertEqual(reply.status_code,202);attempts[provider]=reply.json['attempt']
            for instance in self.app.collectors.values():
                deadline=time.monotonic()+2
                while instance.status(self.first)['login']['state']!='awaiting_sms' and time.monotonic()<deadline:time.sleep(.01)
            reply=self.client.post('/v1/profiles/'+self.first+'/providers/rema/sms',headers=self.auth(self.first),json={'attempt':attempts['trumf'],'code':'123456'})
            self.assertEqual(reply.status_code,404)
            for provider,attempt in attempts.items():
                reply=self.client.post('/v1/profiles/'+self.first+'/providers/'+provider+'/sms',headers=self.auth(self.first),json={'attempt':attempt,'code':'123456'})
                self.assertEqual(reply.status_code,202)
            fingerprints=set()
            for provider,instance in self.app.collectors.items():
                deadline=time.monotonic()+3
                while instance.status(self.first)['login']['state'] in service.ACTIVE and time.monotonic()<deadline:time.sleep(.01)
                value=instance.status(self.first);self.assertTrue(value['connected'],value)
                fingerprints.add(value['account_fingerprint'])
                path=instance.folder(self.first)/'vault.enc'
                self.assertEqual(vault.load(path,self.first,provider)['tokens'],tokens('same-subject'))
                with self.assertRaises(Exception):vault.load(path,self.second,provider)
                if provider!='coop':
                    with self.assertRaises(Exception):vault.load(path,self.first,'coop')
                folder=instance.folder(self.first)/'receipts'/provider;folder.mkdir(parents=True)
                (folder/'index.json').write_text(json.dumps({'ok':True,'count':0,'receipts':[]}))
                url='/v1/profiles/'+self.first+'/providers/'+provider+'/api/archive/'+provider
                response=self.client.get(url,headers=self.auth(self.first))
                self.assertEqual(response.status_code,200);self.assertEqual(response.json['status']['account_fingerprint'],value['account_fingerprint'])
                self.assertEqual(self.client.get(url.replace(self.first,self.second),headers=self.auth(self.first)).status_code,401)
            self.assertEqual(len(fingerprints),3)
        self.app.collectors['rema'].logout(self.first)
        self.assertFalse(self.app.collectors['rema'].status(self.first)['connected'])
        self.assertTrue(self.collector.status(self.first)['connected'])
        self.assertTrue(self.app.collectors['trumf'].status(self.first)['connected'])

    def test_unknown_provider_and_wrong_provider_archive_fail_closed(self):
        for path in ['providers/other/status','providers/rema/api/archive/coop','providers/rema/archive/trumf/'+('f'*64)+'.json']:
            self.assertEqual(self.client.get('/v1/profiles/'+self.first+'/'+path,headers=self.auth(self.first)).status_code,404)
