"""AGPL-3.0: isolated Rema PKCE and Trumf browser login; secrets stay in memory."""
import asyncio
import base64
import hashlib
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit
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


async def finish_sms(page, receive, progress, cancelled, hosts, complete, label):
    deadline = time.monotonic() + 360
    submissions = 0
    while time.monotonic() < deadline:
        if cancelled(): raise LoginError('Innloggingen er avbrutt.')
        if await complete(): return
        if not trusted(page.url, hosts): raise LoginError('Innloggingen videresendte til en ukjent adresse.')
        boxes = page.locator('input[autocomplete="one-time-code"]:visible, input[inputmode="numeric"]:visible, input[name*="code" i]:visible, input[name*="otp" i]:visible, input[type="tel"]:visible:not([name="phoneNumber"])')
        if await boxes.count():
            if submissions >= 3: raise LoginError('SMS-koden ble ikke godkjent. Start innloggingen på nytt.')
            progress('awaiting_sms', 'Skriv inn SMS-koden fra ' + label + '.')
            code = await asyncio.to_thread(receive, deadline)
            if not code: raise LoginError('SMS-koden utløp. Start innloggingen på nytt.')
            if cancelled(): raise LoginError('Innloggingen er avbrutt.')
            if not trusted(page.url, hosts): raise LoginError('Innloggingen kunne ikke bekreftes.')
            progress('checking_sms', 'Kontrollerer SMS-koden hos ' + label + '.')
            count = await boxes.count()
            if count >= len(code):
                for index, digit in enumerate(code): await boxes.nth(index).fill(digit)
            else: await boxes.first.fill(code)
            code = None
            await click(page, ['Bekreft', 'Logg inn', 'Fortsett', 'Send', 'Neste', 'Verifiser'])
            submissions += 1
            await page.wait_for_timeout(1800)
        else:
            errors = page.locator('[role="alert"]:visible, .validation-summary-errors:visible, .field-validation-error:visible')
            if await errors.count(): raise LoginError(label + ' avviste innloggingen. Kontroller opplysningene.')
            await page.wait_for_timeout(300)
    raise LoginError('Innloggingen tok for lang tid. Prøv igjen.')


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
            await page.goto('https://id.rema.no/authorization?' + urlencode(params), wait_until='domcontentloaded', timeout=45000)
            if not trusted(page.url, {'id.rema.no'}): raise LoginError('Rema-innloggingen kunne ikke bekreftes.')
            field = page.locator('input[name="phoneNumber"]:visible, input[type="tel"]:visible').first
            await field.wait_for(state='visible', timeout=20000); await field.fill(phone)
            await click(page, ['Send meg engangskode', 'Send', 'Logg inn', 'Neste'])
            await page.wait_for_timeout(1000)
            async def complete():
                if authorization.get('error'): raise LoginError('Rema svarte med en ugyldig innloggingsbekreftelse.')
                return bool(authorization.get('code'))
            await finish_sms(page, receive, progress, cancelled, {'id.rema.no', 'ae-appen.appspot.com'}, complete, 'Rema')
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
