#!/usr/bin/env python3
"""Synthetic Wardn SSO/lifecycle acceptance. Never stores passwords or tokens in evidence."""
import argparse
import base64
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class ProbeError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Session:
    def __init__(self, allowed):
        self.allowed = allowed
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())

    def request(self, url, method='GET', body=None, headers=None):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname not in self.allowed or parsed.username or parsed.password:
            raise ProbeError('unapproved_transport')
        req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        try:
            response = self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, ValueError):
            raise ProbeError('transport_unavailable') from None
        with response:
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise ProbeError('response_too_large')
            return response.code, response.headers, data, url

    def follow(self, url):
        for _ in range(16):
            result = self.request(url)
            status, headers, _, _ = result
            if status not in (301, 302, 303, 307, 308):
                return result
            target = urllib.parse.urljoin(url, headers.get('Location', ''))
            redirect=urllib.parse.urlsplit(target)
            expect(redirect.scheme=='https' and redirect.hostname in self.allowed and not redirect.username and not redirect.password,'unapproved_redirect')
            if 'oidc_result=' in urllib.parse.urlsplit(target).fragment:
                return status, headers, b'', target
            url = target
        raise ProbeError('too_many_redirects')


def expect(condition, code):
    if not condition:
        raise ProbeError(code)


class CSRF(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tokens = []

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == 'input' and fields.get('name') == 'csrf':
            self.tokens.append(fields.get('value', ''))


class Probe:
    def __init__(self, cfg):
        self.cfg = cfg
        self.issuer = cfg['issuer'].rstrip('/')
        self.origin = urllib.parse.urlsplit(self.issuer)
        self.origin = self.origin.scheme + '://' + self.origin.netloc
        self.hosts = {urllib.parse.urlsplit(self.issuer).hostname}
        self.hosts.update(urllib.parse.urlsplit(value).hostname for value in cfg['apps'].values())
        expect(None not in self.hosts, 'invalid_hosts')
        self.admin = Session(self.hosts)
        self.guest = Session(self.hosts)
        self.user = None
        self.tokens = {}
        self.identities = {}
        self.homes = {}
        self.devices = {}
        self.checks = []

    def native(self, session, route, payload=None):
        url = self.issuer + '/api/' + route
        body = None if payload is None else json.dumps(payload).encode()
        result = session.request(url, 'GET' if payload is None else 'POST', body,
                                 {'Origin': self.origin, 'Content-Type': 'application/json'})
        expect(result[0] == 200, 'native_http')
        response = json.loads(result[2])
        expect(response.get('status') == 'ok', 'native_rejected')
        return response.get('data')

    def login(self, session, org, app, name, password):
        self.native(session, 'login', {'type': 'login', 'signinMethod': 'Password',
                    'organization': org, 'application': app, 'username': name,
                    'password': password, 'method': 'signin', 'language': 'en'})

    def setup(self):
        admin_password = private_file(self.cfg['admin_password_file']).read_text().strip()
        self.login(self.admin, 'built-in', 'app-built-in', self.cfg.get('admin_name', 'admin'), admin_password)
        name = 'wardn-probe-' + uuid.uuid4().hex
        self.user = {'owner': 'saker', 'name': name, 'displayName': 'Wardn probe ' + name[-8:],
                     'email': name + '@example.invalid', 'emailVerified': True,
                     'password': secrets.token_urlsafe(32) + 'Aa1!', 'type': 'normal-user',
                     'createdTime': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        self.native(self.admin, 'add-user', self.user)
        self.login(self.guest, 'saker', self.cfg.get('login_application', 'saker-web'), name, self.user['password'])

    def signins(self):
        apps = self.cfg['apps']
        for label, base in apps.items():
            base = base.rstrip('/')
            start = {'chat': '/auth/oidc', 'peek': '/oauth/oidc/start',
                     'corpus': '/api/v1/auth/oidc/start'}.get(label, '/auth/wardn/start')
            status, _, body, location = self.guest.follow(base + start)
            if label == 'corpus':
                fragment = urllib.parse.parse_qs(urllib.parse.urlsplit(location).fragment)
                expect('oidc_result' in fragment, 'corpus_callback')
                raw = fragment['oidc_result'][0]
                data = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
                expect(data.get('success') and not data['user'].get('is_system_admin'), 'corpus_ordinary_account')
                self.tokens[label] = data['token']
            else:
                expect(status == 200 and urllib.parse.urlsplit(location).hostname == urllib.parse.urlsplit(base).hostname
                       and '/login' not in urllib.parse.urlsplit(location).path, label + '_sso')
                if label.startswith('lanner'):
                    parsed = urllib.parse.urlsplit(location)
                    self.homes[label] = parsed.scheme + '://' + parsed.netloc + '/' + parsed.path.strip('/').split('/')[0]
        self.native_devices()
        self.checks.append('single_wardn_login_all_apps')
        self.check_sessions(True)

    def check_sessions(self, active, expected_name=None):
        for label, original in self.cfg['apps'].items():
            base = self.homes.get(label, original).rstrip('/')
            path = {'chat': '/api/me', 'peek': '/dashboard', 'corpus': '/api/v1/auth/me'}.get(label, '/api/pulse/v1/me')
            headers = {'Authorization': 'Bearer ' + self.tokens[label]} if label == 'corpus' else {}
            status, _, body, _ = self.guest.request(base + path, headers=headers)
            if not active:
                expect(status in (401, 403, 302, 303), label + '_old_session_still_active')
                continue
            expect(status == 200, label + '_session_unavailable')
            if label == 'peek':
                if expected_name:
                    expect(expected_name in body.decode(), 'peek_profile_stale')
                continue
            data = json.loads(body)
            if label == 'chat':
                identity, name = data['identity'], data['identity']['name']
                key = (identity['subject'], identity['tenant_id'])
            elif label == 'corpus':
                user = data.get('user') or data.get('data', {}).get('user')
                expect(user is not None, 'corpus_profile_shape')
                key, name = (user['id'],), user.get('account_name')
            else:
                user = data['data']
                key, name = (user['id'], user['slug']), user['account_name']
                expect(user['display_name'] == 'Participant', 'public_alias_overwritten')
            expect(label not in self.identities or self.identities[label] == key, label + '_identity_changed')
            self.identities[label] = key
            if expected_name:
                expect(name == expected_name, label + '_profile_stale')

        base = self.cfg['apps']['chat'].rstrip('/')
        for platform, tokens in self.devices.items():
            status, _, body, _ = self.guest.request(base + '/api/me',
                              headers={'Authorization': 'Bearer ' + tokens['access_token']})
            expect(status == (200 if active else 401), platform + '_device_state')
            if active and expected_name:
                expect(json.loads(body)['identity']['name'] == expected_name, platform + '_device_profile_stale')
            if not active:
                status, _, _, _ = self.post_json(base + '/auth/mobile/token',
                           {'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token']})
                expect(status == 401, platform + '_revoked_refresh')

    def post_json(self, url, payload):
        return self.guest.request(url, 'POST', json.dumps(payload).encode(),
                                  {'Content-Type': 'application/json'})

    def native_devices(self):
        base = self.cfg['apps']['chat'].rstrip('/')
        for platform in ('mobile', 'desktop'):
            verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
            status, _, body, _ = self.post_json(base + '/auth/native/start',
                    {'platform': platform, 'state': state, 'code_challenge': challenge})
            expect(status == 200, platform + '_start')
            attempt = json.loads(body)
            url = attempt['authorization_url']
            expect('client_secret' not in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query), 'client_secret_in_url')
            status, headers, _, _ = self.guest.request(url)
            expect(status == 302, platform + '_sso')
            callback = urllib.parse.urlsplit(headers['Location'])
            expect(callback.scheme == 'sakerwork' or (callback.scheme == 'http' and callback.hostname == '127.0.0.1'), 'unexpected_device_callback')
            query = urllib.parse.parse_qs(callback.query)
            expect(query.get('state') == [state], 'device_state_mismatch')
            status, _, body, _ = self.post_json(base + '/auth/native/token',
                    {'attempt_id': attempt['attempt_id'], 'code': query['code'][0],
                     'state': state, 'code_verifier': verifier, 'iss': query.get('iss', [''])[0]})
            expect(status == 200, platform + '_exchange')
            tokens = json.loads(body)
            status, _, body, _ = self.post_json(base + '/auth/mobile/token',
                     {'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token']})
            expect(status == 200, platform + '_refresh')
            refreshed = json.loads(body)
            status, _, _, _ = self.post_json(base + '/auth/mobile/token',
                     {'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token']})
            expect(status == 401, platform + '_refresh_replay')
            self.devices[platform] = refreshed
        self.checks.append('mobile_desktop_pkce_refresh_replay_rejection')

    def update(self, **changes):
        expect(self.user is not None and self.user['name'].startswith('wardn-probe-'), 'unowned_fixture')
        query = urllib.parse.urlencode({'id': 'saker/' + self.user['name']})
        user = self.native(self.admin, 'get-user?' + query)
        expect(user is not None and user['name'] == self.user['name'] and user['owner'] == 'saker', 'fixture_mismatch')
        user.update(changes)
        self.native(self.admin, 'update-user?' + query, user)

    def run(self):
        self.setup()
        self.signins()
        new_name = 'Wardn refreshed ' + self.user['name'][-8:]
        self.update(displayName=new_name)
        time.sleep(3)
        self.check_sessions(True, new_name)
        self.checks.append('profile_refresh_identity_and_public_alias_preserved')
        self.update(isForbidden=True)
        time.sleep(3)
        self.check_sessions(False)
        self.update(isForbidden=False)
        time.sleep(3)
        self.check_sessions(False)
        self.checks.append('disable_and_reenable_do_not_revive_old_sessions')
        self.login(self.guest, 'saker', self.cfg.get('login_application', 'saker-web'), self.user['name'], self.user['password'])
        self.signins()
        url = self.issuer + '/api/login/oauth/wardn-global-logout'
        status, _, body, _ = self.guest.request(url)
        expect(status == 200, 'global_logout_confirmation')
        parser = CSRF()
        parser.feed(body.decode())
        expect(len(parser.tokens) == 1 and parser.tokens[0], 'global_logout_csrf')
        status, _, _, _ = self.guest.request(url, 'POST', urllib.parse.urlencode({'csrf': parser.tokens[0]}).encode(),
                 {'Origin': self.origin, 'Content-Type': 'application/x-www-form-urlencoded'})
        expect(status == 200, 'global_logout_failed')
        time.sleep(3)
        self.check_sessions(False)
        self.checks.append('global_logout_revokes_all_old_app_sessions')

    def cleanup(self):
        if self.user is None:
            return True
        expect(self.user['name'].startswith('wardn-probe-'), 'cleanup_unowned_fixture')
        self.native(self.admin, 'delete-user', {'owner': 'saker', 'name': self.user['name']})
        result = self.native(self.admin, 'get-user?' + urllib.parse.urlencode({'id': 'saker/' + self.user['name']}))
        expect(result is None, 'fixture_cleanup_failed')
        return True


def private_file(value):
    path = Path(value).expanduser()
    expect(path.is_file() and stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, 'credential_file_permissions')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='mode 0600 local JSON; see docs/wardn-operations.md')
    parser.add_argument('--output', required=True, help='sanitized JSON receipt')
    args = parser.parse_args()
    os.umask(0o077)
    def interrupted(*_):
        raise ProbeError('interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    receipt = {'schema': 'wardn-probe/v1', 'status': 'FAIL', 'checks': [], 'cleanup': False}
    started = time.monotonic()
    probe = None
    try:
        cfg = json.loads(private_file(args.config).read_text())
        probe = Probe(cfg)
        probe.run()
        receipt['status'] = 'PASS'
    except Exception as error:
        receipt['error'] = str(error) if isinstance(error, ProbeError) else type(error).__name__
    finally:
        if probe:
            receipt['checks'] = probe.checks
            try:
                receipt['cleanup'] = probe.cleanup()
            except Exception:
                receipt['status'], receipt['error'] = 'FAIL', 'fixture_cleanup_failed'
        receipt['duration_seconds'] = round(time.monotonic() - started, 3)
        Path(args.output).write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))
    return 0 if receipt['status'] == 'PASS' and receipt['cleanup'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
