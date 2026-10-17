"""AGPL-3.0: isolated Rema PKCE and Trumf browser login; secrets stay in memory."""
import asyncio
import base64
import hashlib
import re
import secrets
import struct
import time
from urllib.parse import parse_qs, urlencode, urlsplit, urljoin
from coop_login import LoginError

REMA_CALLBACK = 'https://ae-appen.appspot.com/redirect/redirect.html'


def trusted(url, hosts):
    try:
        p = urlsplit(url)
        return p.scheme == 'https' and p.hostname in hosts and p.username is None and p.password is None and p.port in {None, 443}
    except ValueError:
        return False


def phone_number(value):
    value = re.sub(r'[ +()-]', '', value)
    if len(value) == 10 and value.startswith('47'): value = value[2:]
    if not re.fullmatch(r'[4-9][0-9]{7}', value):
        raise LoginError('Skriv inn et norsk mobilnummer med åtte sifre.')
    return value


async def click(page, texts):
    for text in texts:
        button = page.get_by_role('button', name=re.compile(re.escape(text), re.I)).first
        if await button.count() and await button.is_visible() and await button.is_enabled():
            await button.click(timeout=4000)
            return
    await page.locator('input:visible').last.press('Enter')


class RemaVerification:
    """Keep only safe counters/status codes, never challenge answers or request bodies."""
    def __init__(self):
        self.checks=0;self.last_check=0;self.network_errors=0;self.sms_status=None

    def response(self, response):
        url=urlsplit(response.url)
        if trusted(response.url,{'id.rema.no','www.google.com','www.recaptcha.net','recaptcha.google.com'}):
            if '/recaptcha/' in url.path:
                if url.path.endswith('/userverify'):
                    self.checks+=1
                    if self.checks==5:self.last_check=time.monotonic()
                if response.status>=400:self.network_errors+=1
        if trusted(response.url,{'id.rema.no','identitytoolkit.googleapis.com'}) and 'sendverificationcode' in url.path.lower():
            self.sms_status=response.status

    def request_failed(self, request):
        if trusted(request.url,{'id.rema.no','www.google.com','www.recaptcha.net','recaptcha.google.com'}) and '/recaptcha/' in urlsplit(request.url).path:
            if request.failure in {'net::ERR_NAME_NOT_RESOLVED','net::ERR_CONNECTION_TIMED_OUT','net::ERR_CONNECTION_REFUSED','net::ERR_INTERNET_DISCONNECTED','net::ERR_NETWORK_CHANGED'}:
                self.network_errors+=1

    def check(self):
        if self.sms_status==429:
            raise LoginError('Rema har begrenset antall SMS-forsøk. Vent før du prøver igjen. [REMA_SMS_RATE_LIMIT]')
        if self.sms_status is not None and self.sms_status>=400:
            raise LoginError('Rema avviste forespørselen om SMS-kode. Prøv igjen senere. [REMA_SMS_REJECTED]')

    def check_loop(self):
        self.check()
        if self.network_errors>=3:
            raise LoginError('Sikkerhetskontrollen får nettverksfeil. Prøv igjen senere. [REMA_VERIFICATION_NETWORK]')
        if self.checks>=5 and time.monotonic()-self.last_check>=3:
            raise LoginError('Rema gjentar sikkerhetskontrollen uten å godkjenne innloggingen. Stopp og prøv igjen senere. [REMA_VERIFICATION_LOOP]')


async def manual_verification(page, progress):
    """Relay only the visible CAPTCHA frame; the account owner supplies every click."""
    from playwright.async_api import Error
    frames=page.locator('iframe[src*="/recaptcha/"][src*="/bframe"]')
    for index in range(await frames.count()):
        frame=frames.nth(index)
        src=urljoin(page.url,await frame.get_attribute('src') or '')
        if not trusted(src,{'id.rema.no','www.google.com','www.recaptcha.net','recaptcha.google.com'}):continue
        if not await frame.is_visible():continue
        try:
            image=await frame.screenshot(type='png',timeout=2000)
            box=await frame.bounding_box()
            if not box or box['width']<50 or box['height']<50:continue
            width,height=struct.unpack('>II',image[16:24])
            geometry=tuple(round(box[k],1) for k in ['x','y','width','height'])
            progress('verification',{'image':image,'width':width,'height':height,'geometry':geometry})
            action=progress('verification_poll',None)
            if isinstance(action,dict) and action.get('geometry')==geometry:
                # Inputs are restricted to the current CAPTCHA frame, never the login page.
                x,y=action['x']/width*box['width'],action['y']/height*box['height']
                if 0<=x<box['width'] and 0<=y<box['height']:
                    await page.mouse.click(box['x']+x,box['y']+y)
        except Error:
            pass  # The frame can disappear as the user finishes verification.
        await page.wait_for_timeout(250)
        return True
    return False


async def finish_sms(page, receive, progress, cancelled, hosts, complete, label, verification=None):
    from playwright.async_api import Error
    deadline = time.monotonic() + 360
    submissions = 0
    challenge_active = False
    while time.monotonic() < deadline:
        if cancelled(): raise LoginError('Innloggingen er avbrutt.')
        if await complete():
            progress('verification_clear',None)
            return
        if not trusted(page.url, hosts): raise LoginError('Innloggingen videresendte til en ukjent adresse.')
        if verification:verification.check()
        if label=='Rema' and await manual_verification(page,progress):
            if verification:verification.check_loop()
            challenge_active=True
            continue
        if challenge_active:
            progress('verification_clear',None)
            progress('starting','Sikkerhetskontrollen er fullført. Venter på SMS fra '+label+'.')
            challenge_active=False
        boxes = page.locator('input[autocomplete="one-time-code"]:visible, input[inputmode="numeric"]:visible, input[name*="code" i]:visible, input[name*="otp" i]:visible, input[type="tel"]:visible:not([name="phoneNumber"])')
        if await boxes.count():
            if submissions >= 3: raise LoginError('SMS-koden ble ikke godkjent. Start innloggingen på nytt.')
            progress('awaiting_sms', 'Skriv inn SMS-koden fra ' + label + '.')
            code = await asyncio.to_thread(receive, deadline)
            if not code: raise LoginError('SMS-koden utløp. Start innloggingen på nytt.')
            if cancelled(): raise LoginError('Innloggingen er avbrutt.')
            if not trusted(page.url, hosts): raise LoginError('Innloggingen kunne ikke bekreftes.')
            progress('checking_sms', 'Kontrollerer SMS-koden hos ' + label + '.')
            try:
                count = await boxes.count()
                if count >= len(code):
                    for index, digit in enumerate(code): await boxes.nth(index).fill(digit)
                else: await boxes.first.fill(code)
                code = None
                if not await complete():
                    await click(page, ['Bekreft', 'Logg inn', 'Fortsett', 'Send', 'Neste', 'Verifiser'])
            except Error:
                # A successful auto-submit can remove the input before its callback arrives.
                # Only an authenticated, validated completion may suppress the browser error.
                for _ in range(30):
                    if await complete():break
                    if cancelled():raise LoginError('Innloggingen er avbrutt.')
                    await asyncio.sleep(0.1)
                else:raise
            finally:code = None
            submissions += 1
            await page.wait_for_timeout(1800)
        else:
            errors = page.locator('[role="alert"]:visible, .validation-summary-errors:visible, .field-validation-error:visible')
            if any(text.strip() for text in await errors.all_text_contents()):
                raise LoginError(label + ' avviste innloggingen. Kontroller opplysningene.')
            await page.wait_for_timeout(300)
    raise LoginError('Innloggingen tok for lang tid. Prøv igjen.')


async def wait_rema_verification_ready(page, progress):
    if not await page.locator('#recaptcha-container').count():return
    from playwright.async_api import Error
    progress('starting','Laster Rema sin sikkerhetskontroll før mobilnummeret sendes.')
    try:
        anchor=page.locator('iframe[src*="/recaptcha/"][src*="/anchor"]').first
        await anchor.wait_for(state='attached',timeout=20000)
        handle=await anchor.element_handle()
        frame=await handle.content_frame() if handle else None
        if not frame:raise LoginError('Rema sin sikkerhetskontroll kunne ikke lastes. Prøv igjen.')
        await frame.wait_for_load_state('domcontentloaded',timeout=20000)
        await page.wait_for_function('()=>window.grecaptcha && typeof window.grecaptcha.getResponse === "function"',timeout=10000)
    except Error:
        raise LoginError('Rema sin sikkerhetskontroll kunne ikke lastes. Prøv igjen. [REMA_VERIFICATION_LOAD]') from None


async def rema(username, password, receive, progress, cancelled):
    from playwright.async_api import async_playwright
    phone = phone_number(username); username = password = None
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    state = secrets.token_urlsafe(32); authorization = {}
    params = dict(response_type='code', client_id='android-251010', scope='all', redirect_uri=REMA_CALLBACK,
                  code_challenge=challenge, code_challenge_method='S256', state=state)
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-dev-shm-usage'])
        try:
            context = await browser.new_context(locale='nb-NO')
            def capture(browser_request):
                parts = urlsplit(browser_request.url)
                if not trusted(browser_request.url, {'ae-appen.appspot.com'}) or parts.path != urlsplit(REMA_CALLBACK).path: return
                values = parse_qs(parts.query)
                if values.get('state') != [state] or len(values.get('code', [])) != 1: authorization['error'] = True
                else: authorization['code'] = values['code'][0]
            async def callback(route):
                capture(route.request)
                await route.fulfill(status=200, body='Gå tilbake til Phocket.')
            await context.route(REMA_CALLBACK + '*', callback)
            page = await context.new_page()
            page.on('request', capture)
            verification=RemaVerification()
            page.on('response',verification.response)
            page.on('requestfailed',verification.request_failed)
            await page.goto('https://id.rema.no/authorization?' + urlencode(params), wait_until='domcontentloaded', timeout=45000)
            if not trusted(page.url, {'id.rema.no'}): raise LoginError('Rema-innloggingen kunne ikke bekreftes.')
            field = page.locator('input[name="phoneNumber"]:visible, input[type="tel"]:visible').first
            await field.wait_for(state='visible', timeout=20000)
            await wait_rema_verification_ready(page,progress)
            await field.fill(phone)
            await click(page, ['Send meg engangskode', 'Send', 'Logg inn', 'Neste'])
            progress('starting','Mobilnummeret er sendt til Rema. Venter på sikkerhetskontroll eller SMS.')
            await page.wait_for_timeout(500)
            async def complete():
                if authorization.get('error'): raise LoginError('Rema svarte med en ugyldig innloggingsbekreftelse.')
                return bool(authorization.get('code'))
            await finish_sms(page, receive, progress, cancelled, {'id.rema.no', 'ae-appen.appspot.com'}, complete, 'Rema', verification)
            progress('finishing', 'Fullfører tilkoblingen til Rema.')
            response = await context.request.post('https://id.rema.no/token', form=dict(grant_type='authorization_code',
                client_id='android-251010', code=authorization['code'], redirect_uri=REMA_CALLBACK, code_verifier=verifier))
            if response.status != 200: raise LoginError('Rema kunne ikke fullføre innloggingen.')
            tokens = await response.json()
            if not all(isinstance(tokens.get(k), str) and tokens[k] for k in ('access_token', 'refresh_token')):
                raise LoginError('Rema returnerte ingen varig innlogging.')
            tokens['_phone'] = phone
            return tokens
        finally: await browser.close()


async def trumf(username, password, receive, progress, cancelled):
    from playwright.async_api import async_playwright
    phone = phone_number(username); username = None
    hosts = {'www.trumf.no', 'id.trumf.no'}
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-dev-shm-usage'])
        try:
            context = await browser.new_context(locale='nb-NO')
            page = await context.new_page()
            response = await context.request.get('https://www.trumf.no/api/auth/csrf')
            if response.status != 200: raise LoginError('Trumf-innloggingen er utilgjengelig.')
            csrf = (await response.json())['csrfToken']
            response = await context.request.post('https://www.trumf.no/api/auth/signin/trumf-personal',
                form={'csrfToken': csrf, 'callbackUrl': 'https://www.trumf.no/', 'json': 'true'})
            destination = response.url
            if 'application/json' in response.headers.get('content-type', ''):
                destination = (await response.json()).get('url', '')
            if not trusted(destination, hosts): raise LoginError('Trumf-innloggingen kunne ikke bekreftes.')
            await page.goto(destination, wait_until='domcontentloaded', timeout=45000)
            if not trusted(page.url, hosts): raise LoginError('Trumf-innloggingen kunne ikke bekreftes.')
            field = page.locator('input[type="tel"]:visible, input[autocomplete="username"]:visible, input[name="username"]:visible').first
            await field.wait_for(state='visible', timeout=20000); await field.fill(phone)
            await click(page, ['Neste', 'Fortsett', 'Logg inn', 'Videre'])
            field = page.locator('input[type="password"]:visible').first
            await field.wait_for(state='visible', timeout=20000)
            if not trusted(page.url, hosts): raise LoginError('Trumf-innloggingen kunne ikke bekreftes.')
            await field.fill(password); password = None
            await click(page, ['Logg inn', 'Neste', 'Fortsett'])
            await page.wait_for_timeout(1000)
            session = {}
            async def complete():
                if trusted(page.url, {'www.trumf.no'}):
                    reply = await context.request.get('https://www.trumf.no/api/auth/session')
                    if reply.status == 200:
                        token = (await reply.json()).get('accessToken')
                        if isinstance(token, str) and token:
                            session['access_token'] = token
                            return True
                return False
            await finish_sms(page, receive, progress, cancelled, hosts, complete, 'Trumf')
            progress('finishing', 'Fullfører tilkoblingen til Trumf.')
            session['storage_state'] = await context.storage_state()
            return session
        finally:
            password = None
            await browser.close()
