"""User-controlled verification images and clicks must stay with their login owner."""
import base64
import time
import unittest
from pathlib import Path
import service
import test_service as fixtures

PNG=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j4aQAAAAASUVORK5CYII=')

class VerificationTests(unittest.TestCase):
    setUp=fixtures.CollectorTests.setUp
    tearDown=fixtures.CollectorTests.tearDown
    auth=fixtures.CollectorTests.auth

    def challenge(self):
        self.owner=self.app.collectors['rema'];self.attempt='c'*48
        with self.owner.db() as conn:
            conn.execute('INSERT INTO profiles(id,device) VALUES(?,?)',(self.first,'synthetic-device'))
            conn.execute('INSERT INTO attempts(id,profile,state,message,created,expires) VALUES(?,?,?,?,?,?)',(self.attempt,self.first,'starting','Opening',time.time(),time.time()+60))
        self.owner.progress(self.attempt,'verification',{'image':PNG,'width':1,'height':1,'geometry':(5,5,1,1)})
        self.url='/v1/profiles/'+self.first+'/providers/rema/verification'
        self.view=self.owner.status(self.first)['login']['verification']['view_id']

    def test_only_attempt_owner_can_view_image_and_control_current_frame(self):
        self.challenge()
        result=self.client.get(self.url+'/'+self.attempt,headers=self.auth(self.first))
        self.assertEqual(result.status_code,200);self.assertEqual(result.data,PNG)
        self.assertEqual(result.headers['Cache-Control'],'private, no-store');result.close()
        other=self.url.replace(self.first,self.second)
        self.assertEqual(self.client.get(other+'/'+self.attempt,headers=self.auth(self.second)).status_code,404)
        self.assertEqual(self.client.get(other+'/'+self.attempt,headers=self.auth(self.first)).status_code,401)
        self.assertEqual(self.client.get(self.url.replace('/providers/rema','/providers/coop')+'/'+self.attempt,headers=self.auth(self.first)).status_code,404)
        body={'attempt':self.attempt,'view_id':self.view,'x':0.5,'y':0.5}
        self.assertEqual(self.client.post(other,headers=self.auth(self.second),json=body).status_code,404)
        self.assertEqual(self.client.post(self.url,headers=self.auth(self.first),json=body).status_code,202)
        self.assertEqual(self.owner.progress(self.attempt,'verification_poll',None),{'x':0.5,'y':0.5,'geometry':(5,5,1,1)})
        for path in Path(self.temp.name).rglob('*'):
            if path.is_file():self.assertNotIn(PNG,path.read_bytes())

    def test_invalid_clicks_stale_geometry_and_cancelled_attempt_are_rejected(self):
        self.challenge()
        body={'attempt':self.attempt,'view_id':self.view,'x':0,'y':0}
        for x in [-1,1,10000,'NaN','Infinity',None]:
            self.assertEqual(self.client.post(self.url,headers=self.auth(self.first),json={**body,'x':x}).status_code,400)
        self.owner.progress(self.attempt,'verification',{'image':PNG,'width':1,'height':1,'geometry':(10,10,1,1)})
        self.assertEqual(self.client.post(self.url,headers=self.auth(self.first),json=body).status_code,409)
        self.owner.cancel(self.first)
        self.assertEqual(self.client.get(self.url+'/'+self.attempt,headers=self.auth(self.first)).status_code,409)
        self.assertNotIn(self.attempt,self.owner.verifications)
        self.assertIsNone(self.owner.status(self.first)['login']['verification'])
