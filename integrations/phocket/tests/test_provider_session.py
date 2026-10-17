"""Provider refreshes must preserve account identity and checkpoint rotated secrets."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import requests
import provider_session
import vault
from test_service import tokens


class RefreshTests(unittest.TestCase):
    def test_rema_rotation_keeps_phone_device_and_encrypted_provider_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'key').write_bytes(b'k'*64)
            original={**tokens('one'),'_phone':'91234567'}
            (root/'rema_tokens.json').write_text(json.dumps(original));(root/'rema_device.json').write_text('{"device_id":"private-device"}')
            expected=vault.account(original,'rema')
            env={'GROCIOUS_SERVICE_KEY_FILE':str(root/'key'),'GROCERY_DATA':tmp,'GROCIOUS_PROFILE_ID':'a'*64,'GROCIOUS_PROVIDER':'rema','GROCIOUS_PROFILE_VAULT':str(root/'vault.enc'),'GROCIOUS_EXPECTED_ACCOUNT':expected}
            with patch.dict(os.environ,env):
                vault.save(root/'vault.enc','a'*64,{'tokens':original,'provider':'rema'},expected)
                reply=SimpleNamespace(raise_for_status=lambda:None,json=lambda:{**tokens('one'),'refresh_token':'rotated'})
                with patch('provider_session.requests.post',return_value=reply) as post:
                    headers=provider_session.rema_headers()
                self.assertEqual(post.call_args.args[0],'https://id.rema.no/token')
                self.assertEqual(headers['x-device-id'],'private-device');self.assertEqual(headers['x-mobile-nr'],'91234567')
                self.assertEqual(vault.load(root/'vault.enc','a'*64,'rema')['tokens']['refresh_token'],'rotated')
                self.assertNotIn(b'rotated',(root/'vault.enc').read_bytes())

    def test_trumf_session_refresh_rejects_different_account_before_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'key').write_bytes(b'k'*64)
            original={**tokens('one'),'storage_state':{'cookies':[],'origins':[]}}
            (root/'trumf_tokens.json').write_text(json.dumps(original))
            expected=vault.account(original,'trumf')
            env={'GROCIOUS_SERVICE_KEY_FILE':str(root/'key'),'GROCERY_DATA':tmp,'GROCIOUS_PROFILE_ID':'a'*64,'GROCIOUS_PROVIDER':'trumf','GROCIOUS_PROFILE_VAULT':str(root/'vault.enc'),'GROCIOUS_EXPECTED_ACCOUNT':expected}
            with patch.dict(os.environ,env):
                vault.save(root/'vault.enc','a'*64,{'tokens':original,'provider':'trumf'},expected)
                session=requests.Session()
                def reply(subject):return SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'accessToken':tokens(subject)['access_token']})
                with patch('provider_session.requests.Session',return_value=session),patch.object(session,'get',return_value=reply('one')):
                    self.assertIs(provider_session.trumf_session(),session)
                before=(root/'vault.enc').read_bytes()
                with patch('provider_session.requests.Session',return_value=session),patch.object(session,'get',return_value=reply('other')):
                    with self.assertRaises(ValueError):provider_session.trumf_session()
                self.assertEqual((root/'vault.enc').read_bytes(),before)
