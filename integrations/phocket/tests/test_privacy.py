import hashlib
import io
import json
import shutil
import sqlite3
import unittest
import zipfile
from unittest.mock import patch

import test_service as fixtures
import service
import vault


class CollectorPrivacyTests(unittest.TestCase):
    setUp=fixtures.CollectorTests.setUp
    tearDown=fixtures.CollectorTests.tearDown
    auth=fixtures.CollectorTests.auth
    wait_state=fixtures.CollectorTests.wait_state

    def seed(self, instance, profile, value):
        instance.reserve(profile,hashlib.sha256(value.encode()).hexdigest())
        folder=instance.folder(profile)
        vault.atomic(folder/'receipts'/instance.provider/'receipt.json',value.encode())
        vault.atomic(folder/'vault.enc',b'SECRET-SESSION-TOKEN')
        return folder

    def test_export_contains_only_own_receipts_from_all_providers_without_tokens(self):
        self.seed(self.collector,self.first,'MY-COOP-RECEIPT')
        self.seed(self.collector,self.second,'OTHER-PRIVATE-RECEIPT')
        self.seed(self.app.collectors['rema'],self.first,'MY-REMA-RECEIPT')
        reply=self.client.get('/v1/profiles/'+self.first+'/export',headers=self.auth(self.first))
        self.assertEqual(reply.status_code,200)
        with zipfile.ZipFile(io.BytesIO(reply.data)) as archive:
            body=b''.join(archive.read(name) for name in archive.namelist())
            self.assertIn(b'MY-COOP-RECEIPT',body);self.assertIn(b'MY-REMA-RECEIPT',body)
            self.assertNotIn(b'OTHER-PRIVATE',body);self.assertNotIn(b'SECRET-SESSION',body)
            self.assertTrue(all(name.endswith('/receipt.json') for name in archive.namelist()))
        reply.close()
        self.assertEqual(self.client.get('/v1/profiles/'+self.first+'/export',headers=self.auth(self.second)).status_code,401)

    def test_purge_is_profile_scoped_idempotent_and_rejects_old_login_requests(self):
        own=self.seed(self.collector,self.first,'own')
        other=self.seed(self.collector,self.second,'other')
        rema=self.seed(self.app.collectors['rema'],self.first,'rema')
        path='/v1/profiles/'+self.first+'/purge';generation='c'*48
        self.assertEqual(self.client.post(path,headers=self.auth(self.second),json={'generation':generation}).status_code,401)
        for _ in range(2):self.assertEqual(self.client.post(path,headers=self.auth(self.first),json={'generation':generation}).status_code,200)
        self.assertFalse(own.exists());self.assertFalse(rema.exists());self.assertTrue(other.exists())
        with self.collector.db() as conn:self.assertIsNone(conn.execute('SELECT * FROM profiles WHERE id=?',(self.first,)).fetchone())
        with self.assertRaises(service.ServiceError):self.collector.start(self.first,'synthetic-user','synthetic-password')
        async def login(*args):return fixtures.tokens('fresh-account')
        self.collector.login_runner=login
        with patch.object(self.collector,'schedule_sync'):
            self.collector.start(self.first,'synthetic-user','synthetic-password',generation)
            self.wait_state(self.first,{'connected'})
        self.collector.purge(self.first,generation)
        self.assertTrue(self.collector.status(self.first)['connected'])
        restarted=service.Collector(self.collector.root)
        try:self.assertTrue(restarted.status(self.first)['connected'])
        finally:
            restarted.executor.shutdown(wait=True);restarted.sync_executor.shutdown(wait=True)

    def test_purge_pauses_a_busy_profile_and_waits_for_worker_before_unlinking(self):
        folder=self.seed(self.collector,self.first,'own')
        self.collector.active_sync.add(self.first)
        try:
            with self.assertRaises(service.ServiceError):self.collector.purge(self.first,'d'*48)
            self.assertTrue(folder.exists())
            with self.collector.db() as conn:self.assertEqual(conn.execute('SELECT enabled FROM profiles WHERE id=?',(self.first,)).fetchone()[0],0)
        finally:self.collector.active_sync.discard(self.first)
        self.collector.purge(self.first,'d'*48)
        self.assertFalse(folder.exists())

    def test_purge_stops_other_providers_even_while_first_provider_is_busy(self):
        self.seed(self.collector,self.first,'own')
        rema=self.seed(self.app.collectors['rema'],self.first,'rema')
        self.collector.active_sync.add(self.first)
        try:
            reply=self.client.post('/v1/profiles/'+self.first+'/purge',headers=self.auth(self.first),json={'generation':'e'*48})
            self.assertEqual(reply.status_code,409)
            self.assertFalse(rema.exists())
        finally:self.collector.active_sync.discard(self.first)

    def test_restored_old_database_and_tokens_cannot_revive_erased_profile(self):
        from pathlib import Path
        folder=self.seed(self.collector,self.first,'old-receipt')
        old_folder=Path(self.temp.name)/'old-folder';shutil.copytree(folder,old_folder)
        backup=sqlite3.connect(Path(self.temp.name)/'old-profiles.sqlite3')
        with self.collector.db() as conn:conn.backup(backup)
        self.collector.purge(self.first,'f'*48)
        with self.collector.db() as conn:backup.backup(conn)
        backup.close();shutil.copytree(old_folder,folder)
        restored=service.Collector(self.collector.root)
        try:
            self.assertFalse(restored.status(self.first)['connected'])
            self.assertFalse(folder.exists())
        finally:
            restored.executor.shutdown(wait=True);restored.sync_executor.shutdown(wait=True)
