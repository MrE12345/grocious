"""AGPL-3.0: profile-isolated grocery collector and authenticated HTTP API."""
import asyncio
import hashlib
import hmac
import io
import json
import logging
import math
import os
import queue
import re
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file
import coop_login
from browser_login import BrowserAttempt
import provider_login
import vault

ACTIVE = ('starting','awaiting_sms','checking_sms','finishing')


class ServiceError(Exception):
    def __init__(self, message, status=409): self.message,self.status=message,status


class Collector:
    def __init__(self, root, provider="coop"):
        if provider not in {"coop", "rema", "trumf"}: raise ServiceError("Ukjent dagligvarekjede.",404)
        self.provider = provider
        self.label = {"coop":"Coop", "rema":"Rema", "trumf":"Trumf"}[provider]
        self.root=Path(root); self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.database=self.root/'profiles.sqlite3'; self.guard=threading.RLock()
        self.codes={}; self.verifications={}; self.browser_attempts={}; self.active_sync=set(); self.executor=ThreadPoolExecutor(max_workers=2)
        self.sync_executor=ThreadPoolExecutor(max_workers=2)
        self.login_runner=coop_login.authenticate if provider=="coop" else getattr(provider_login,provider)
        with self.db() as conn:
            conn.executescript('''
            CREATE TABLE IF NOT EXISTS profiles(id TEXT PRIMARY KEY, account TEXT UNIQUE, device TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1, sync_state TEXT NOT NULL DEFAULT 'idle', sync_error TEXT NOT NULL DEFAULT '',
                last_sync REAL, next_sync REAL NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY, profile TEXT NOT NULL, state TEXT NOT NULL,
                message TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, submissions INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS attempt_profiles ON attempts(profile,created);
            ''')
            if not any(r[1]=='bound_hash' for r in conn.execute('PRAGMA table_info(profiles)')):
                conn.execute('ALTER TABLE profiles ADD COLUMN bound_hash TEXT')
            if not any(r[1]=='privacy_generation' for r in conn.execute('PRAGMA table_info(profiles)')):
                conn.execute('ALTER TABLE profiles ADD COLUMN privacy_generation TEXT')
            conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS profile_account_binding ON profiles(bound_hash)')
            conn.execute("UPDATE attempts SET state='failed',message='Tjenesten startet på nytt. Start innloggingen på nytt.' WHERE state IN ('starting','awaiting_sms','checking_sms','finishing')")
            conn.execute("UPDATE profiles SET sync_state='idle' WHERE sync_state='running'")
        os.chmod(self.database,0o600)
        # A restored database/token folder must not silently revive an erased account.
        for marker in (self.root/'erasures').glob('*.json'):
            generation=json.loads(marker.read_text())['generation'];profile=marker.stem
            with self.db() as conn:
                row=conn.execute('SELECT privacy_generation FROM profiles WHERE id=?',(profile,)).fetchone()
            if (row and row[0]!=generation) or (not row and self.folder(profile).exists()):
                self.purge(profile,generation)

    def db(self):
        conn=sqlite3.connect(self.database,timeout=10); conn.row_factory=sqlite3.Row
        return conn

    def folder(self, profile):
        if not re.fullmatch('[a-f0-9]{64}',profile): raise ServiceError('Ugyldig brukerprofil.',404)
        return self.root/'profiles'/profile

    def _expire_browser(self):
        with self.guard,self.db() as conn:
            for attempt,value in list(self.browser_attempts.items()):
                if value.expires<time.time():
                    self.browser_attempts.pop(attempt,None)
                    conn.execute("UPDATE attempts SET state='failed',message='Rema-forsøket utløp. Start et nytt forsøk.' WHERE id=? AND state IN ('starting','finishing')",(attempt,))

    def status(self, profile):
        self._expire_browser()
        with self.db() as conn:
            row=conn.execute('SELECT * FROM profiles WHERE id=?',(profile,)).fetchone()
            attempt=conn.execute('SELECT id,state,message,expires,submissions FROM attempts WHERE profile=? ORDER BY created DESC LIMIT 1',(profile,)).fetchone()
        login=dict(attempt) if attempt else None
        if login:
            with self.guard:
                challenge=self.verifications.get(login['id']) if login['state'] in ACTIVE and login['expires']>time.time() else None
                login['verification']={k:challenge[k] for k in ['view_id','width','height']} if challenge else None
                login['browser']=login['id'] in self.browser_attempts and login['state'] in ACTIVE and login['expires']>time.time()
        return {'connected':bool(row and row['enabled'] and (self.folder(profile)/'vault.enc').exists()),
                'account_fingerprint':row['account'] if row else None,
                'login':login,
                'sync':{'state':row['sync_state'],'message':row['sync_error'],'last_success':row['last_sync']} if row else {'state':'idle','message':'','last_success':None}}

    def start(self, profile, username, password, privacy_generation=None, *, browser=False):
        self._expire_browser()
        direct=BrowserAttempt(username) if browser and self.provider=='rema' else None
        if browser and not direct:raise ServiceError('Nettlesertesten støtter bare Rema.',400)
        if not isinstance(username,str) or not 1<=len(username.strip())<=254 or not isinstance(password,str) or not (0 if self.provider=='rema' else 1)<=len(password)<=1024:
            raise ServiceError('Fyll inn mobilnummer' + ('.' if self.provider=='rema' else ' og passord.'),400)
        with self.guard, self.db() as conn:
            marker=self.root/'erasures'/(profile+'.json')
            self.folder(profile)  # Validate before constructing or reading any profile path.
            if marker.exists() and json.loads(marker.read_text())['generation'] != privacy_generation:
                raise ServiceError('Kvitteringsarkivet er slettet. Oppdater Phocket før du kobler til på nytt.')
            count=conn.execute("SELECT count(*) FROM attempts WHERE state IN ('starting','awaiting_sms','checking_sms','finishing')").fetchone()[0]
            if count>=2: raise ServiceError('To innlogginger pågår. Prøv igjen om litt.',429)
            recent=conn.execute('SELECT count(*) FROM attempts WHERE profile=? AND created>?',(profile,time.time()-600)).fetchone()[0]
            if recent>=4: raise ServiceError('For mange innloggingsforsøk. Vent ti minutter.',429)
            if conn.execute("SELECT 1 FROM attempts WHERE profile=? AND state IN ('starting','awaiting_sms','checking_sms','finishing')",(profile,)).fetchone():
                raise ServiceError('En innlogging pågår allerede. Fullfør eller avbryt den først.')
            if profile in self.active_sync: raise ServiceError('Kvitteringer hentes nå. Prøv innloggingen igjen når hentingen er ferdig.')
            conn.execute('INSERT OR IGNORE INTO profiles(id,device) VALUES(?,?)',(profile,str(uuid.uuid4())))
            conn.execute('UPDATE profiles SET privacy_generation=? WHERE id=?',(privacy_generation,profile))
            attempt=secrets.token_hex(24); now=time.time()
            conn.execute('INSERT INTO attempts(id,profile,state,message,created,expires) VALUES(?,?,?,?,?,?)',
                         (attempt,profile,'starting','Fullfør innloggingen i Rema-fanen og lim inn returadressen her.' if direct else 'Åpner '+self.label+'-innloggingen.',now,direct.expires if direct else now+420))
            conn.commit()
            if direct:self.browser_attempts[attempt]=direct
            else:
                self.codes[attempt]=queue.Queue(maxsize=1)
                self.executor.submit(self._login,profile,attempt,username.strip(),password)
        return attempt

    def start_browser(self, profile, phone, generation=None):
        attempt=self.start(profile,phone,'',generation,browser=True)
        with self.guard:return {'attempt':attempt,'authorization_url':self.browser_attempts[attempt].authorization_url()}

    def complete_browser(self, profile, attempt, return_url):
        self._expire_browser()
        with self.guard,self.db() as conn:
            row=self._attempt(profile,attempt)
            pending=self.browser_attempts.get(attempt)
            if row['state']!='starting' or row['expires']<time.time() or not pending:
                raise ServiceError('Rema-forsøket er brukt, avbrutt eller utløpt. Start et nytt forsøk.')
            try:code=pending.code_from_return(return_url)
            except coop_login.LoginError as exc:raise ServiceError(str(exc),400) from None
            self.browser_attempts.pop(attempt)
            conn.execute("UPDATE attempts SET state='finishing',message='Bekrefter innloggingen hos Rema.' WHERE id=?",(attempt,))
        return_url=None
        # Reuse the existing binding, encryption, erasure and receipt scheduling guards.
        self._login(profile,attempt,None,None,tokens_runner=lambda:pending.exchange(code))

    def reserve(self, profile, bound_hash):
        if not isinstance(bound_hash,str) or not re.fullmatch('[a-f0-9]{64}',bound_hash):raise ServiceError('Ugyldig kontobinding.',400)
        with self.guard,self.db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row=conn.execute('SELECT bound_hash,account FROM profiles WHERE id=?',(profile,)).fetchone()
            if row and row['bound_hash'] and row['bound_hash']!=bound_hash:raise ServiceError('Profilen tilhører en annen ' + self.label + '-konto.')
            if row and row['account'] and hashlib.sha256(row['account'].encode()).hexdigest()!=bound_hash:raise ServiceError('Profilen tilhører en annen ' + self.label + '-konto.')
            if conn.execute('SELECT 1 FROM profiles WHERE bound_hash=? AND id<>?',(bound_hash,profile)).fetchone():raise ServiceError(self.label+'-kontoen tilhører en annen bruker.')
            conn.execute('INSERT OR IGNORE INTO profiles(id,device) VALUES(?,?)',(profile,str(uuid.uuid4())))
            conn.execute('UPDATE profiles SET bound_hash=? WHERE id=?',(bound_hash,profile))

    def _attempt(self, profile, attempt):
        with self.db() as conn:
            row=conn.execute('SELECT * FROM attempts WHERE profile=? AND id=?',(profile,attempt)).fetchone()
        if not row: raise ServiceError('Innloggingsforsøket finnes ikke.',404)
        return row

    def progress(self, attempt, state, message):
        if state=='verification_clear':
            with self.guard:self.verifications.pop(attempt,None)
            return
        if state=='verification_poll':
            with self.guard:
                value=self.verifications.get(attempt)
                if value:
                    try:return value['actions'].get_nowait()
                    except queue.Empty:pass
            return None
        if state=='verification':
            image=message['image'];width=message['width'];height=message['height']
            if not isinstance(image,bytes) or not image.startswith(b'\x89PNG\r\n\x1a\n') or len(image)>2*1024*1024 or not (1<=width<=1600 and 1<=height<=1200):
                raise ServiceError('Sikkerhetskontrollen kunne ikke vises.')
            with self.guard:
                value=self.verifications.get(attempt)
                if not value or value['geometry']!=message['geometry']:
                    value={'view_id':secrets.token_hex(16),'geometry':message['geometry'],'actions':queue.Queue(maxsize=8),'click_times':[]}
                    self.verifications[attempt]=value
                value.update(image=image,width=width,height=height)
            state='starting';message='Rema krever en sikkerhetskontroll. Fullfør bildebekreftelsen nedenfor for å få SMS-koden.'
        with self.db() as conn:
            conn.execute("UPDATE attempts SET state=?,message=? WHERE id=? AND state IN ('starting','awaiting_sms','checking_sms','finishing')",(state,message,attempt))

    def _login(self, profile, attempt, username, password, *, tokens_runner=None):
        def cancelled():
            row=self._attempt(profile,attempt)
            return row['state'] not in ACTIVE or row['expires']<time.time()
        def receive(deadline):
            while time.monotonic()<deadline and not cancelled():
                try:return self.codes[attempt].get(timeout=1)
                except queue.Empty:pass
            return None
        phase='browser_login'
        try:
            tokens=tokens_runner() if tokens_runner else asyncio.run(self.login_runner(username,password,receive,lambda s,m:self.progress(attempt,s,m),cancelled))
            username=password=None
            if cancelled(): return
            phase='account_identity'
            fingerprint=vault.account(tokens,self.provider)
            phase='account_binding'
            with self.guard, self.db() as conn:
                conn.execute('BEGIN IMMEDIATE')
                if self._attempt(profile,attempt)['state'] not in ACTIVE:return
                current=conn.execute('SELECT * FROM profiles WHERE id=?',(profile,)).fetchone()
                if current['account'] and current['account']!=fingerprint:
                    raise ServiceError('Denne profilen er bundet til en annen ' + self.label + '-konto. Kvitteringene kan ikke blandes.')
                bound_hash=hashlib.sha256(fingerprint.encode()).hexdigest()
                if current['bound_hash'] and current['bound_hash']!=bound_hash:
                    raise ServiceError(self.label+'-kontoen samsvarer ikke med tidligere kvitteringsimport.')
                if conn.execute('SELECT 1 FROM profiles WHERE bound_hash=? AND id<>?',(bound_hash,profile)).fetchone():
                    raise ServiceError(self.label+'-kontoen er allerede knyttet til en annen bruker.')
                if conn.execute('SELECT 1 FROM profiles WHERE account=? AND id<>?',(fingerprint,profile)).fetchone():
                    raise ServiceError(self.label+'-kontoen er allerede koblet til en annen bruker.')
                conn.execute('UPDATE profiles SET account=?,bound_hash=?,enabled=1,next_sync=0,sync_error=\'\' WHERE id=?',(fingerprint,bound_hash,profile))
                phase='session_storage'
                vault.save(self.folder(profile)/'vault.enc',profile,{'tokens':tokens,'device':current['device'],'provider':self.provider},fingerprint)
                conn.execute("UPDATE attempts SET state='connected',message=? WHERE id=?",(self.label+' er tilkoblet. Første kvitteringshenting starter nå.',attempt))
            phase='collection_schedule'
            self.schedule_sync(profile)
        except Exception as exc:
            if isinstance(exc,ServiceError): message=exc.message
            elif isinstance(exc,coop_login.LoginError): message=str(exc)
            else:
                kind = 'IO' if isinstance(exc,OSError) else 'DATABASE' if isinstance(exc,sqlite3.Error) else 'FORMAT' if isinstance(exc,(ValueError,KeyError,IndexError,TypeError)) else 'INTERNAL'
                diagnostic = self.provider.upper()+'_'+phase.upper()+'_'+kind
                # Never log exception messages or locals: browser errors may contain credentials.
                logging.getLogger(__name__).warning('provider_login_failure code=%s',diagnostic)
                message=self.label+'-innloggingen feilet. Prøv igjen; tidligere kvitteringer er bevart. ['+diagnostic+']'
            self.progress(attempt,'failed',message)
        finally:
            username=password=None
            with self.guard:
                self.codes.pop(attempt,None)
                self.verifications.pop(attempt,None)

    def sms(self, profile, attempt, code):
        if not isinstance(code,str) or not re.fullmatch('[0-9]{6}',code): raise ServiceError('SMS-koden må ha seks sifre.',400)
        with self.guard, self.db() as conn:
            row=self._attempt(profile,attempt)
            if row['state']!='awaiting_sms' or row['expires']<time.time() or attempt not in self.codes:
                raise ServiceError('SMS-koden kan ikke brukes nå. Oppdater status eller start på nytt.')
            if row['submissions']>=3:raise ServiceError('For mange SMS-forsøk. Start innloggingen på nytt.',429)
            try:self.codes[attempt].put_nowait(code)
            except queue.Full:raise ServiceError('En SMS-kode blir allerede kontrollert.')
            conn.execute("UPDATE attempts SET submissions=submissions+1,state='checking_sms',message='Kontrollerer SMS-koden.' WHERE id=?",(attempt,))

    def verification_image(self, profile, attempt):
        with self.guard:
            row=self._attempt(profile,attempt)
            value=self.verifications.get(attempt)
            if row['state'] not in ACTIVE or row['expires']<time.time() or not value:
                raise ServiceError('Sikkerhetskontrollen er ikke aktiv. Oppdater status.',409)
            return value['image']

    def verification_click(self, profile, body):
        attempt=body.get('attempt')
        with self.guard:
            self.verification_image(profile,attempt)
            value=self.verifications[attempt]
            if body.get('view_id')!=value['view_id']:raise ServiceError('Bildet ble oppdatert. Prøv igjen.')
            try:x,y=float(body.get('x')),float(body.get('y'))
            except (TypeError,ValueError):raise ServiceError('Ugyldig plassering i sikkerhetskontrollen.',400) from None
            if not (math.isfinite(x) and math.isfinite(y) and 0<=x<value['width'] and 0<=y<value['height']):
                raise ServiceError('Klikket er utenfor sikkerhetskontrollen.',400)
            now=time.monotonic();value['click_times']=[t for t in value['click_times'] if t>now-60]
            if len(value['click_times'])>=90:raise ServiceError('Vent litt før du klikker igjen.',429)
            try:value['actions'].put_nowait({'x':x,'y':y,'geometry':value['geometry']})
            except queue.Full:raise ServiceError('Tidligere klikk behandles. Vent litt.',429) from None
            value['click_times'].append(now)

    def cancel(self, profile):
        with self.guard,self.db() as conn:
            for row in conn.execute('SELECT id FROM attempts WHERE profile=?',(profile,)):
                self.verifications.pop(row['id'],None)
                self.browser_attempts.pop(row['id'],None)
            conn.execute("UPDATE attempts SET state='cancelled',message='Innloggingen er avbrutt.' WHERE profile=? AND state IN ('starting','awaiting_sms','checking_sms','finishing')",(profile,))

    def logout(self, profile):
        self.cancel(profile)
        with self.guard, self.db() as conn:
            if profile in self.active_sync:raise ServiceError('Henting pågår. Vent til den er ferdig før du logger ut.')
            conn.execute('UPDATE profiles SET enabled=0 WHERE id=?',(profile,))
            (self.folder(profile)/'vault.enc').unlink(missing_ok=True)

    def purge(self, profile, generation):
        folder=self.folder(profile)
        if not isinstance(generation,str) or not re.fullmatch('[a-f0-9]{48}',generation):
            raise ServiceError('Ugyldig sletteforespørsel.',400)
        with self.guard,self.db() as conn:
            current=conn.execute('SELECT privacy_generation FROM profiles WHERE id=?',(profile,)).fetchone()
            if current and current[0]==generation:
                return  # A fresh, explicit login after this erasure must survive delayed retries.
            marker=self.root/'erasures'/(profile+'.json')
            vault.atomic(marker,json.dumps({'generation':generation}).encode())
            self.cancel(profile)
            conn.execute('UPDATE profiles SET enabled=0 WHERE id=?',(profile,));conn.commit()
            attempts=[r[0] for r in conn.execute('SELECT id FROM attempts WHERE profile=?',(profile,))]
            if profile in self.active_sync or any(attempt in self.codes for attempt in attempts):
                raise ServiceError('Venter på at innlogging eller kvitteringshenting avsluttes.')
            if folder.is_symlink():folder.unlink()
            elif folder.is_dir():shutil.rmtree(folder)
            for attempt in attempts:self.verifications.pop(attempt,None)
            conn.execute('DELETE FROM attempts WHERE profile=?',(profile,))
            conn.execute('DELETE FROM profiles WHERE id=?',(profile,))

    def schedule_sync(self, profile):
        with self.guard, self.db() as conn:
            if profile in self.active_sync:return
            if len(self.active_sync)>=4:return
            if conn.execute("SELECT 1 FROM attempts WHERE profile=? AND state IN ('starting','awaiting_sms','checking_sms','finishing')",(profile,)).fetchone():return
            row=conn.execute('SELECT * FROM profiles WHERE id=? AND enabled=1 AND account IS NOT NULL',(profile,)).fetchone()
            if not row or not (self.folder(profile)/'vault.enc').exists():return
            self.active_sync.add(profile)
            conn.execute("UPDATE profiles SET sync_state='running',sync_error='' WHERE id=?",(profile,))
            conn.commit(); self.sync_executor.submit(self._sync,profile,dict(row))

    def _sync(self, profile, row):
        try:
            value=vault.load(self.folder(profile)/'vault.enc',profile,self.provider)
            archive=self.folder(profile)/'receipts'; archive.mkdir(parents=True,exist_ok=True,mode=0o700)
            with tempfile.TemporaryDirectory(prefix=self.provider+'-job-') as temporary:
                work=Path(temporary); (work/'receipts').symlink_to(archive.resolve(),target_is_directory=True)
                vault.atomic(work/(self.provider+'_tokens.json'),json.dumps(value['tokens']).encode())
                if self.provider=='coop':vault.atomic(work/'coop_session.json',json.dumps({'headers':{'x-deviceid':value['device']}}).encode())
                if self.provider=='rema':vault.atomic(work/'rema_device.json',json.dumps({'device_id':value['device']}).encode())
                env={**os.environ,'GROCERY_DATA':temporary,'GROCIOUS_PROFILE_ID':profile,
                     'GROCIOUS_PROFILE_VAULT':str(self.folder(profile)/'vault.enc'),'GROCIOUS_EXPECTED_ACCOUNT':row['account'],'GROCIOUS_PROVIDER':self.provider}
                command=['python','/app/coop_archive.py'] if self.provider=='coop' else ['python','/app/provider_archive.py',self.provider]
                if (archive/self.provider/('full_sync.json' if self.provider=='coop' else 'index.json')).exists():command.append('--incremental')
                result=subprocess.run(command,env=env,capture_output=True,timeout=3600)
                if result.returncode:raise RuntimeError('collection failed')
            with self.db() as conn:
                conn.execute("UPDATE profiles SET sync_state='ready',sync_error='',last_sync=?,next_sync=? WHERE id=?",(time.time(),time.time()+900,profile))
        except Exception:
            with self.db() as conn:
                conn.execute("UPDATE profiles SET sync_state='error',sync_error=?,next_sync=? WHERE id=?",(self.label+'-hentingen feilet. Prøv igjen eller forny innloggingen.',time.time()+900,profile))
        finally:
            with self.guard:self.active_sync.discard(profile)

    def tick(self):
        self._expire_browser()
        with self.db() as conn:
            profiles=[r[0] for r in conn.execute('SELECT id FROM profiles WHERE enabled=1 AND account IS NOT NULL AND next_sync<=? LIMIT 10',(time.time(),))]
        for profile in profiles:self.schedule_sync(profile)

    def archive(self, profile, suffix):
        root=self.folder(profile)/'receipts'/self.provider
        if suffix=='api/archive/'+self.provider:
            status=self.status(profile)
            if not status['connected']:raise ServiceError('Logg inn på '+self.label+' for å hente kvitteringer.')
            if not (root/'index.json').exists():raise ServiceError('Første kvitteringshenting pågår. Prøver igjen snart.')
            value=json.loads((root/'index.json').read_text())
            value['status']={'state':status['sync']['state'],'account_fingerprint':status['account_fingerprint']}
            return value
        match=re.fullmatch(r'archive/'+self.provider+r'/([a-f0-9]{64})(?:\.json|/file/([A-Za-z0-9_.-]{1,180}))',suffix)
        if not match:raise ServiceError('Arkivfilen finnes ikke.',404)
        record_path=root/match[1]/'receipt.json'
        if not record_path.exists():raise ServiceError('Kvitteringen finnes ikke.',404)
        record=json.loads(record_path.read_text())
        if not match[2]:return record
        filename=match[2]
        entry=next((d for d in record.get('documents',[]) if d['filename']==filename),None)
        path=root/match[1]/filename
        if filename in {'.','..'} or not entry or not path.is_file():raise ServiceError('Arkivfilen finnes ikke.',404)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=entry['sha256']:raise ServiceError('Arkivfilens kontrollsum stemmer ikke.')
        return path,entry['mimetype']


def create_app(collector=None, *, background=False):
    app=Flask(__name__); app.config['MAX_CONTENT_LENGTH']=16384
    collector=collector or Collector(os.getenv('GROCIOUS_DATA','/data'))
    collectors={'coop':collector, **{p:Collector(collector.root/'providers'/p,p) for p in ('rema','trumf')}}
    app.collector=collector; app.collectors=collectors
    def selected(provider):
        if provider not in collectors: raise ServiceError('Ukjent dagligvarekjede.',404)
        return collectors[provider]
    @app.errorhandler(ServiceError)
    def service_error(exc):return jsonify(error=exc.message),exc.status
    @app.after_request
    def private(response):
        response.headers['Cache-Control']='private, no-store';response.headers['X-Content-Type-Options']='nosniff'
        return response
    @app.before_request
    def authenticate():
        if request.path in {'/livez','/source'}:return
        profile=(request.view_args or {}).get('profile','')
        if not re.fullmatch('[a-f0-9]{64}',profile):abort(404)
        expected='Bearer '+hmac.new(vault.secret(),b'profile:'+profile.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(request.headers.get('Authorization',''),expected):abort(401)
    @app.get('/livez')
    def livez():return jsonify(ok=True)
    @app.get('/source')
    def source():
        content=io.BytesIO()
        with tarfile.open(fileobj=content,mode='w:gz') as tar:
            for path in sorted(Path('/source').rglob('*')):
                if path.is_file() and '__pycache__' not in path.parts:tar.add(path,arcname='grocious-multiuser/'+str(path.relative_to('/source')))
        content.seek(0);return send_file(content,mimetype='application/gzip',as_attachment=True,download_name='grocious-multiuser-source.tar.gz')
    @app.get('/v1/profiles/<profile>/status')
    @app.get('/v1/profiles/<profile>/providers/<provider>/status')
    def status(profile,provider="coop"):
        collector=selected(provider)
        return jsonify(collector.status(profile))
    @app.post('/v1/profiles/<profile>/login')
    @app.post('/v1/profiles/<profile>/providers/<provider>/login')
    def login(profile,provider="coop"):
        collector=selected(provider)
        body=request.get_json() or {};return jsonify(attempt=collector.start(profile,body.get('username'),body.get('password'),body.get('privacy_generation'))),202
    @app.post('/v1/profiles/<profile>/providers/rema/browser-start')
    def browser_start(profile):
        body=request.get_json() or {}
        try:result=selected('rema').start_browser(profile,body.get('username'),body.get('privacy_generation'))
        except coop_login.LoginError as exc:raise ServiceError(str(exc),400) from None
        return jsonify(result),202
    @app.post('/v1/profiles/<profile>/providers/rema/browser-complete')
    def browser_complete(profile):
        body=request.get_json() or {}
        selected('rema').complete_browser(profile,body.get('attempt'),body.get('return_url'))
        return jsonify(ok=True),202
    @app.post('/v1/profiles/<profile>/reserve')
    @app.post('/v1/profiles/<profile>/providers/<provider>/reserve')
    def reserve(profile,provider="coop"):
        collector=selected(provider)
        body=request.get_json() or {};collector.reserve(profile,body.get('account_hash'));return jsonify(ok=True)
    @app.post('/v1/profiles/<profile>/sms')
    @app.post('/v1/profiles/<profile>/providers/<provider>/sms')
    def sms(profile,provider="coop"):
        collector=selected(provider)
        body=request.get_json() or {};collector.sms(profile,body.get('attempt'),body.get('code'));return jsonify(ok=True),202
    @app.get('/v1/profiles/<profile>/verification/<attempt>')
    @app.get('/v1/profiles/<profile>/providers/<provider>/verification/<attempt>')
    def verification_image(profile,attempt,provider="coop"):
        body=selected(provider).verification_image(profile,attempt)
        return send_file(io.BytesIO(body),mimetype='image/png')
    @app.post('/v1/profiles/<profile>/verification')
    @app.post('/v1/profiles/<profile>/providers/<provider>/verification')
    def verification_click(profile,provider="coop"):
        selected(provider).verification_click(profile,request.get_json() or {})
        return jsonify(ok=True),202
    @app.post('/v1/profiles/<profile>/cancel')
    @app.post('/v1/profiles/<profile>/providers/<provider>/cancel')
    def cancel(profile,provider="coop"):
        collector=selected(provider)
        collector.cancel(profile);return jsonify(ok=True)
    @app.post('/v1/profiles/<profile>/logout')
    @app.post('/v1/profiles/<profile>/providers/<provider>/logout')
    def logout(profile,provider="coop"):
        collector=selected(provider)
        collector.logout(profile);return jsonify(ok=True)
    @app.post('/v1/profiles/<profile>/purge')
    def purge(profile):
        generation=(request.get_json(silent=True) or {}).get('generation')
        busy=False
        for instance in collectors.values():
            try:instance.purge(profile,generation)
            except ServiceError as exc:
                if exc.status!=409:raise
                busy=True
        if busy:raise ServiceError('Venter på at pågående innlogging eller kvitteringshenting avsluttes.')
        return jsonify(ok=True)
    @app.get('/v1/profiles/<profile>/export')
    def export(profile):
        export_root=collector.root/'export-tmp';export_root.mkdir(mode=0o700,exist_ok=True)
        content=tempfile.TemporaryFile(dir=export_root)
        try:
            with zipfile.ZipFile(content,'w',zipfile.ZIP_DEFLATED) as archive:
                for provider,instance in collectors.items():
                    root=instance.folder(profile)/'receipts'
                    if root.is_symlink():raise ServiceError('Arkivet kunne ikke eksporteres.',409)
                    for path in sorted(root.rglob('*')) if root.is_dir() else []:
                        if path.is_file() and not path.is_symlink() and root.resolve() in path.resolve().parents:
                            archive.write(path,provider+'/'+str(path.relative_to(root)))
            content.seek(0)
            response=send_file(content,mimetype='application/zip',as_attachment=True,download_name='grocious-originaler.zip')
            response.call_on_close(content.close)
            return response
        except Exception:
            content.close();raise
    @app.post('/v1/profiles/<profile>/sync')
    @app.post('/v1/profiles/<profile>/providers/<provider>/sync')
    def sync(profile,provider="coop"):
        collector=selected(provider)
        collector.schedule_sync(profile);return jsonify(ok=True),202
    @app.get('/v1/profiles/<profile>/<path:suffix>')
    @app.get('/v1/profiles/<profile>/providers/<provider>/<path:suffix>')
    def archive(profile,suffix,provider="coop"):
        collector=selected(provider)
        value=collector.archive(profile,suffix)
        if isinstance(value,tuple):return send_file(value[0],mimetype=value[1])
        return jsonify(value)
    if background:
        def worker():
            while True:
                try:
                    for instance in collectors.values():instance.tick()
                except Exception:pass
                time.sleep(15)
        threading.Thread(target=worker,daemon=True,name='grocery-collection').start()
    return app


if os.getenv('GROCIOUS_SERVICE_KEY_FILE'):
    app=create_app(background=True)
