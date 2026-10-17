"""AGPL-3.0: per-attempt Coop OAuth/PKCE browser session with in-memory SMS."""
import asyncio
import base64
import hashlib
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit

CLIENT_ID = '7WrQEdeXwUudArpQVjmZEvrTgVs1WkRr'
CALLBACK = 'https://login.coop.no/android/no.coop.members/callback'


class LoginError(Exception):
    pass


def trusted_page(url):
    try:
        parsed = urlsplit(url)
        return parsed.scheme == 'https' and parsed.hostname == 'login.coop.no' and parsed.username is None and parsed.password is None and parsed.port in {None,443}
    except ValueError:return False


async def authenticate(username, password, receive_code, progress, cancelled):
    from playwright.async_api import Error, TimeoutError
    phase = {'step': 'opening'}
    labels = {
        'opening': 'åpning av Coop-innloggingen',
        'identifier': 'innsending av brukernavn',
        'password': 'innsending av passord',
        'sms_wait': 'venting på SMS-kode',
        'sms_submit': 'bekreftelse av SMS-koden',
        'callback': 'fullføring etter SMS-koden',
        'token': 'henting av innloggingstoken',
    }
    try:
        return await _authenticate(username, password, receive_code, progress, cancelled, phase)
    except LoginError:
        raise
    except TimeoutError:
        raise LoginError('Coop svarte ikke under ' + labels[phase['step']] +
                         '. Start innloggingen på nytt. [COOP_' + phase['step'].upper() + '_TIMEOUT]') from None
    except Error:
        raise LoginError('Nettleseren stoppet under ' + labels[phase['step']] +
                         '. Prøv igjen. [COOP_' + phase['step'].upper() + '_BROWSER]') from None
    finally:
        username = password = None


async def _authenticate(username, password, receive_code, progress, cancelled, phase):
    from playwright.async_api import async_playwright, Error
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    state = secrets.token_urlsafe(32); authorization = {}
    params = dict(response_type='code',client_id=CLIENT_ID,redirect_uri=CALLBACK,audience='https://api.coop.no',
                  scope='openid profile offline_access',code_challenge=challenge,code_challenge_method='S256',state=state)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
        try:
            context = await browser.new_context(locale='nb-NO')
            page = await context.new_page()
            def capture_callback(browser_request):
                parsed = urlsplit(browser_request.url)
                values = parse_qs(parsed.query)
                if trusted_page(browser_request.url) and parsed.path == urlsplit(CALLBACK).path:
                    if values.get('state') == [state] and len(values.get('code',[])) == 1:
                        authorization['code'] = values['code'][0]
                    else:
                        authorization['invalid'] = True
            page.on('request',capture_callback)
            async def callback(route):
                capture_callback(route.request)
                await route.fulfill(status=200,body='Innlogging mottatt. Du kan gå tilbake til Phocket.')
            await context.route(CALLBACK+'*', callback)
            await page.goto('https://login.coop.no/authorize?'+urlencode(params),wait_until='domcontentloaded',timeout=45000)
            if not trusted_page(page.url): raise LoginError('Coop-innloggingen videresendte til en ukjent adresse.')
            user = page.locator('#username, input[name="username"]').first
            await user.wait_for(state='visible',timeout=20000)
            phase['step'] = 'identifier'
            await user.fill(username); username = None
            await user.press('Enter')
            field = page.locator('input[name="password"]:visible').first
            await field.wait_for(state='visible',timeout=20000)
            if not trusted_page(page.url): raise LoginError('Coop-innloggingen kunne ikke bekreftes.')
            phase['step'] = 'password'
            await field.fill(password); password = None
            await field.press('Enter')
            deadline = time.monotonic()+360
            submissions = 0
            while time.monotonic() < deadline:
                if cancelled(): raise LoginError('Innloggingen er avbrutt.')
                if authorization.get('invalid'):
                    raise LoginError('Coop svarte med en ugyldig innloggingsbekreftelse. Start på nytt. [COOP_CALLBACK_STATE]')
                if authorization.get('code'): break
                if not trusted_page(page.url): raise LoginError('Coop-innloggingen kunne ikke bekreftes.')
                code_field = page.locator('input[name="code"]:visible, input[autocomplete="one-time-code"]:visible').first
                if await code_field.count():
                    if submissions >= 3: raise LoginError('SMS-koden ble ikke godkjent. Start innloggingen på nytt.')
                    phase['step'] = 'sms_wait'
                    progress('awaiting_sms','Skriv inn SMS-koden fra Coop.')
                    code = await asyncio.to_thread(receive_code, deadline)
                    if not code: raise LoginError('SMS-koden utløp. Start innloggingen på nytt.')
                    if cancelled(): raise LoginError('Innloggingen er avbrutt.')
                    if not trusted_page(page.url): raise LoginError('Coop-innloggingen kunne ikke bekreftes.')
                    progress('checking_sms','Kontrollerer SMS-koden hos Coop.')
                    phase['step'] = 'sms_submit'
                    try:
                        await code_field.fill(code); code = None
                        # Some Coop pages submit as the sixth digit is filled. A captured,
                        # state-validated callback already proves this step completed.
                        if not authorization.get('code') and await code_field.count():
                            await code_field.press('Enter', timeout=5000, no_wait_after=True)
                    except Error:
                        if not authorization.get('code') or authorization.get('invalid'):
                            raise
                    finally:
                        code = None
                    submissions += 1
                    phase['step'] = 'callback'
                    await page.wait_for_timeout(400)
                else:
                    errors = page.locator('[role="alert"]:visible, #error-message:visible, .ulp-input-error-message:visible')
                    if any(text.strip() for text in await errors.all_text_contents()):
                        raise LoginError('Coop avviste innloggingen. Kontroller brukernavn og passord.')
                    await page.wait_for_timeout(400)
            if not authorization.get('code'): raise LoginError('Innloggingen tok for lang tid. Prøv igjen.')
            if authorization.get('invalid'):
                raise LoginError('Coop svarte med en ugyldig innloggingsbekreftelse. Start på nytt. [COOP_CALLBACK_STATE]')
            phase['step'] = 'token'
            progress('finishing','Fullfører tilkoblingen til Coop.')
            response = await context.request.post('https://login.coop.no/oauth/token',form=dict(
                grant_type='authorization_code',client_id=CLIENT_ID,code=authorization['code'],redirect_uri=CALLBACK,code_verifier=verifier))
            if response.status != 200: raise LoginError('Coop kunne ikke fullføre innloggingen. Prøv igjen. [COOP_TOKEN_HTTP_' + str(response.status) + ']')
            tokens = await response.json()
            if not all(isinstance(tokens.get(k),str) and tokens[k] for k in ['access_token','refresh_token']):
                raise LoginError('Coop returnerte ingen varig innlogging. Prøv igjen.')
            return tokens
        finally:
            password = username = None
            try:
                await browser.close()
            except Error:
                pass
