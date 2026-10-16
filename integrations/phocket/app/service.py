"""AGPL-3.0: profile-isolated grocery collector and authenticated HTTP API."""
import asyncio
import hashlib
import hmac
import io
import json
import os
import queue
import re
import secrets
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file
import coop_login
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
        self.codes={}; self.active_sync=set(); self.executor=ThreadPoolExecutor(max_workers=2)
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
            conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS profile_account_binding ON profiles(bound_hash)')
            conn.execute("UPDATE attempts SET state='failed',message='Tjenesten startet på nytt. Start innloggingen på nytt.' WHERE state IN ('starting','awaiting_sms','checking_sms','finishing')")
            conn.execute("UPDATE profiles SET sync_state='idle' WHERE sync_state='running'")
        os.chmod(self.database,0o600)

    def db(self):
        conn=sqlite3.connect(self.database,timeout=10); conn.row_factory=sqlite3.Row
        return conn

    def folder(self, profile):
        if not re.fullmatch('[a-f0-9]{64}',profile): raise ServiceError('Ugyldig brukerprofil.',404)
        return self.root/'profiles'/profile

    def status(self, profile):
        with self.db() as conn:
            row=conn.execute('SELECT * FROM profiles WHERE id=?',(profile,)).fetchone()
            attempt=conn.execute('SELECT id,state,message,expires,submissions FROM attempts WHERE profile=? ORDER BY created DESC LIMIT 1',(profile,)).fetchone()
        return {'connected':bool(row and row['enabled'] and (self.folder(profile)/'vault.enc').exists()),
                'account_fingerprint':row['account'] if row else None,
                'login':dict(attempt) if attempt else None,
                'sync':{'state':row['sync_state'],'message':row['sync_error'],'last_success':row['last_sync']} if row else {'state':'idle','message':'','last_success':None}}

    def start(self, profile, username, password):
        if not isinstance(username,str) or not 1<=len(username.strip())<=254 or not isinstance(password,str) or not (0 if self.provider=='rema' else 1)<=len(password)<=1024:
            raise ServiceError('Fyll inn mobilnummer' + ('.' if self.provider=='rema' else ' og passord.'),400)
        with self.guard, self.db() as conn:
            count=conn.execute("SELECT count(*) FROM attempts WHERE state IN ('starting','awaiting_sms','checking_sms','finishing')").fetchone()[0]
            if count>=2: raise ServiceError('To innlogginger pågår. Prøv igjen om litt.',429)
            recent=conn.execute('SELECT count(*) FROM attempts WHERE profile=? AND created>?',(profile,time.time()-600)).fetchone()[0]
            if recent>=4: raise ServiceError('For mange innloggingsforsøk. Vent ti minutter.',429)
            if conn.execute("SELECT 1 FROM attempts WHERE profile=? AND state IN ('starting','awaiting_sms','checking_sms','finishing')",(profile,)).fetchone():
                raise ServiceError('En innlogging pågår allerede. Fullfør eller avbryt den først.')
            if profile in self.active_sync: raise ServiceError('Kvitteringer hentes nå. Prøv innloggingen igjen når hentingen er ferdig.')
            conn.execute('INSERT OR IGNORE INTO profiles(id,device) VALUES(?,?)',(profile,str(uuid.uuid4())))
            attempt=secrets.token_hex(24); now=time.time()
            conn.execute('INSERT INTO attempts(id,profile,state,message,created,expires) VALUES(?,?,?,?,?,?)',
                         (attempt,profile,'starting','Åpner '+self.label+'-innloggingen.',now,now+420))
            conn.commit(); self.codes[attempt]=queue.Queue(maxsize=1)
            self.executor.submit(self._login,profile,attempt,username.strip(),password)
        return attempt

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
        with self.db() as conn:
            conn.execute("UPDATE attempts SET state=?,message=? WHERE id=? AND state IN ('starting','awaiting_sms','checking_sms','finishing')",(state,message,attempt))

    def _login(self, profile, attempt, username, password):
        def cancelled():
            row=self._attempt(profile,attempt)
            return row['state'] not in ACTIVE or row['expires']<time.time()
        def receive(deadline):
            while time.monotonic()<deadline and not cancelled():
                try:return self.codes[attempt].get(timeout=1)
                except queue.Empty:pass
            return None
        try:
            tokens=asyncio.run(self.login_runner(username,password,receive,lambda s,m:self.progress(attempt,s,m),cancelled))
            username=password=None
            if cancelled(): return
            fingerprint=vault.account(tokens,self.provider)
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
                vault.save(self.folder(profile)/'vault.enc',profile,{'tokens':tokens,'device':current['device'],'provider':self.provider},fingerprint)
                conn.execute("UPDATE attempts SET state='connected',message=? WHERE id=?",(self.label+' er tilkoblet. Første kvitteringshenting starter nå.',attempt))
            self.schedule_sync(profile)
        except Exception as exc:
            message=exc.message if isinstance(exc,ServiceError) else str(exc) if isinstance(exc,coop_login.LoginError) else self.label+'-innloggingen feilet. Prøv igjen; tidligere kvitteringer er bevart.'
            self.progress(attempt,'failed',message)
        finally:
            username=password=None
            with self.guard:self.codes.pop(attempt,None)

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

    def cancel(self, profile):
        with self.db() as conn:
            conn.execute("UPDATE attempts SET state='cancelled',message='Innloggingen er avbrutt.' WHERE profile=? AND state IN ('starting','awaiting_sms','checking_sms','finishing')",(profile,))

    def logout(self, profile):
        self.cancel(profile)
        with self.guard, self.db() as conn:
            if profile in self.active_sync:raise ServiceError('Henting pågår. Vent til den er ferdig før du logger ut.')
            conn.execute('UPDATE profiles SET enabled=0 WHERE id=?',(profile,))
            (self.folder(profile)/'vault.enc').unlink(missing_ok=True)

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
        body=request.get_json() or {};return jsonify(attempt=collector.start(profile,body.get('username'),body.get('password'))),202
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
