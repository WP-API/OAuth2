"""End-to-end PKCE checks against a running WordPress with the OAuth2 plugin.

Uses real HTTP only: cookie login, the consent form, the token endpoint and a
Bearer API call. Redirects are never followed, so every Location is checked.
Run it through run.sh, which starts WordPress Playground first.
"""
import base64, hashlib, html, http.cookiejar, json, os, re, secrets, sys, urllib.error, urllib.parse, urllib.request

BASE = os.environ.get('E2E_BASE_URL', 'http://127.0.0.1:9400').rstrip('/')
CALLBACK = 'http://127.0.0.1:9876/callback'
results = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def opener(jar=None):
    handlers = [NoRedirect()]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    return urllib.request.build_opener(*handlers)


def send(op, url, data=None, headers=None):
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        r = op.open(req, timeout=30)
    except urllib.error.HTTPError as e:
        r = e
    return r.status, r.headers, r.read().decode('utf-8', 'replace')


def check(name, ok, detail=''):
    results.append((name, bool(ok)))
    print(('PASS ' if ok else 'FAIL ') + name + ('' if ok else f'  -- {detail}'))


def pkce_pair():
    verifier = secrets.token_urlsafe(48)[:64]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return verifier, challenge


def login():
    jar = http.cookiejar.CookieJar()
    op = opener(jar)
    send(op, BASE + '/wp-login.php')
    status, headers, _ = send(op, BASE + '/wp-login.php', {
        'log': 'admin', 'pwd': 'password', 'wp-submit': 'Log In', 'testcookie': '1',
        'redirect_to': BASE + '/wp-admin/',
    })
    logged_in = any(c.name.startswith('wordpress_logged_in') for c in jar)
    check('login with username and password', status == 302 and logged_in, f'status={status}')
    return op


def authorize(op, client_id, params, response_type='code', submit='authorize'):
    """Run the authorize step. Returns (location, form_shown)."""
    query = [('action', 'oauth2_authorize'), ('response_type', response_type),
             ('client_id', client_id), ('redirect_uri', CALLBACK)]
    query += list(params.items()) if isinstance(params, dict) else params
    url = BASE + '/wp-login.php?' + urllib.parse.urlencode(query)
    status, headers, body = send(op, url)
    if status in (301, 302, 303):
        return headers.get('Location'), False
    if status != 200 or 'oauth2_authorize_form' not in body:
        return f'UNEXPECTED {status}: {body[:300]}', False

    action = html.unescape(re.search(r'id="oauth2_authorize_form" action="([^"]+)"', body).group(1))
    nonce = re.search(r'name="_wpnonce" value="([^"]+)"', body).group(1)
    status, headers, body = send(op, urllib.parse.urljoin(BASE, action), {
        '_wpnonce': nonce, '_wp_http_referer': action, 'wp-submit': submit,
    })
    return headers.get('Location', f'UNEXPECTED {status}: {body[:300]}'), True


def query_of(location):
    parts = urllib.parse.urlsplit(location or '')
    return parts, dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True)), \
        dict(urllib.parse.parse_qsl(parts.fragment, keep_blank_values=True))


def token(params, json_body=False, query=None):
    url = BASE + '/?rest_route=/oauth2/access_token'
    if query:
        url += '&' + urllib.parse.urlencode(query)
    if json_body:
        status, _, body = send(opener(), url, json.dumps(params).encode(), {'Content-Type': 'application/json'})
    else:
        status, _, body = send(opener(), url, params)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, {'raw': body[:300]}


def rejected_code(status, data):
    return status in (400, 404) and data.get('code') == 'oauth2.client.check_authorization_code.invalid_code'


def get_code(op, client_id, params):
    location, _ = authorize(op, client_id, params)
    return query_of(location)[1].get('code'), location


def main():
    clients = json.loads(urllib.request.urlopen(BASE + '/e2e-clients.json').read())
    required, optional = clients['required'], clients['optional']
    op = login()

    # Discovery advertises PKCE methods.
    _, _, body = send(opener(), BASE + '/.well-known/oauth-authorization-server')
    try:
        methods = json.loads(body).get('code_challenge_methods_supported')
    except ValueError:
        methods = None
    check('RFC 8414 metadata lists code_challenge_methods_supported', methods and 'S256' in methods, body[:200])

    # 1. Happy path: PKCE-required client with S256.
    verifier, challenge = pkce_pair()
    location, form = authorize(op, required, {'state': 'st-1', 'code_challenge': challenge, 'code_challenge_method': 'S256'})
    parts, q, _ = query_of(location)
    code = q.get('code')
    check('S256: consent form shown, redirect goes to client callback',
          form and location.startswith(CALLBACK) and code and q.get('state') == 'st-1', location)
    status, data = token({'grant_type': 'authorization_code', 'client_id': required, 'code': code, 'code_verifier': verifier})
    access = data.get('access_token')
    check('S256: code + correct verifier exchanges for a token', status == 200 and access, f'{status} {data}')
    status, _, body = send(opener(), BASE + '/?rest_route=/wp/v2/users/me', headers={'Authorization': f'Bearer {access}'})
    check('S256: Bearer token authenticates /wp/v2/users/me', status == 200 and json.loads(body).get('slug') == 'admin', f'{status} {body[:200]}')
    status, data = token({'grant_type': 'authorization_code', 'client_id': required, 'code': code, 'code_verifier': verifier})
    check('S256: code cannot be reused', rejected_code(status, data), f'{status} {data}')

    # 2. JSON body carries the verifier too.
    verifier, challenge = pkce_pair()
    code, _ = get_code(op, required, {'code_challenge': challenge, 'code_challenge_method': 'S256'})
    status, data = token({'grant_type': 'authorization_code', 'client_id': required, 'code': code, 'code_verifier': verifier}, json_body=True)
    check('S256: verifier in a JSON body is accepted', status == 200 and data.get('access_token'), f'{status} {data}')

    # 3. Wrong verifier, and the code is burned afterwards.
    verifier, challenge = pkce_pair()
    code, _ = get_code(op, required, {'code_challenge': challenge, 'code_challenge_method': 'S256'})
    wrong, _ = pkce_pair()
    status, data = token({'grant_type': 'authorization_code', 'client_id': required, 'code': code, 'code_verifier': wrong})
    check('wrong verifier is rejected with invalid_grant', status == 400 and data.get('data', {}).get('error') == 'invalid_grant', f'{status} {data}')
    status, data = token({'grant_type': 'authorization_code', 'client_id': required, 'code': code, 'code_verifier': verifier})
    check('code is deleted after a failed verifier attempt', rejected_code(status, data), f'{status} {data}')

    # 4. Missing verifier.
    verifier, challenge = pkce_pair()
    code, _ = get_code(op, required, {'code_challenge': challenge, 'code_challenge_method': 'S256'})
    status, data = token({'grant_type': 'authorization_code', 'client_id': required, 'code': code})
    check('missing verifier is rejected', status == 400 and 'missing_verifier' in data.get('code', ''), f'{status} {data}')

    # 5. Verifier only in the URL query is ignored.
    verifier, challenge = pkce_pair()
    code, _ = get_code(op, required, {'code_challenge': challenge, 'code_challenge_method': 'S256'})
    status, data = token({'grant_type': 'authorization_code', 'client_id': required, 'code': code}, query={'code_verifier': verifier})
    check('verifier in the URL query string is ignored', status == 400 and 'missing_verifier' in data.get('code', ''), f'{status} {data}')

    # 6. Required client without PKCE: error redirect to the client, not wp-admin.
    location, form = authorize(op, required, {'state': 'st-6'})
    parts, q, _ = query_of(location)
    check('required client without challenge: invalid_request redirect to callback, state kept',
          not form and location.startswith(CALLBACK) and q.get('error') == 'invalid_request' and q.get('state') == 'st-6', location)

    # 7. Required client with plain.
    verifier, _ = pkce_pair()
    location, form = authorize(op, required, {'code_challenge': verifier, 'code_challenge_method': 'plain'})
    q = query_of(location)[1]
    check('required client with plain: rejected before consent', not form and q.get('error') == 'invalid_request' and 'S256' in q.get('error_description', ''), location)

    # 8. Malformed parameters.
    location, form = authorize(op, optional, [('code_challenge[]', 'x')])
    check('array-valued code_challenge: invalid_request', not form and query_of(location)[1].get('error') == 'invalid_request', location)
    location, form = authorize(op, optional, {'code_challenge_method': 'S256'})
    check('method without challenge: invalid_request', not form and query_of(location)[1].get('error') == 'invalid_request', location)
    location, form = authorize(op, optional, {'code_challenge': 'a' * 43, 'code_challenge_method': 'S512'})
    check('unsupported method: invalid_request', not form and query_of(location)[1].get('error') == 'invalid_request', location)
    location, form = authorize(op, optional, {'code_challenge': 'short', 'code_challenge_method': 'S256'})
    check('malformed S256 challenge: invalid_request', not form and query_of(location)[1].get('error') == 'invalid_request', location)

    # 9. Optional client with plain works end to end.
    verifier, _ = pkce_pair()
    code, location = get_code(op, optional, {'code_challenge': verifier, 'code_challenge_method': 'plain'})
    status, data = token({'grant_type': 'authorization_code', 'client_id': optional, 'code': code, 'code_verifier': verifier})
    check('optional client with plain: exchanges for a token', status == 200 and data.get('access_token'), f'{location} {status} {data}')

    # 10. Optional client without PKCE still works (backwards compatible).
    code, location = get_code(op, optional, {})
    status, data = token({'grant_type': 'authorization_code', 'client_id': optional, 'code': code})
    check('optional client without PKCE: exchanges for a token', status == 200 and data.get('access_token'), f'{location} {status} {data}')

    # 11. Verifier sent for a non-PKCE code (downgrade attempt).
    code, _ = get_code(op, optional, {})
    verifier, _ = pkce_pair()
    status, data = token({'grant_type': 'authorization_code', 'client_id': optional, 'code': code, 'code_verifier': verifier})
    check('verifier for a code issued without PKCE is rejected', status == 400 and 'unexpected_verifier' in data.get('code', ''), f'{status} {data}')

    # 12. Code issued to one client cannot be redeemed by another.
    verifier, challenge = pkce_pair()
    code, _ = get_code(op, required, {'code_challenge': challenge, 'code_challenge_method': 'S256'})
    status, data = token({'grant_type': 'authorization_code', 'client_id': optional, 'code': code, 'code_verifier': verifier})
    check('code cannot be redeemed by a different client', rejected_code(status, data), f'{status} {data}')

    # 13. Implicit grant refused for a PKCE-required client, reported in the fragment.
    location, form = authorize(op, required, {'state': 'st-13'}, response_type='token')
    _, _, frag = query_of(location)
    check('implicit grant for required client: unauthorized_client in fragment',
          not form and location.startswith(CALLBACK) and frag.get('error') == 'unauthorized_client' and frag.get('state') == 'st-13', location)

    # 14. Cancel on the consent form.
    verifier, challenge = pkce_pair()
    location, form = authorize(op, required, {'code_challenge': challenge, 'code_challenge_method': 'S256'}, submit='cancel')
    check('cancel on consent: access_denied to callback', form and query_of(location)[1].get('error') == 'access_denied', location)

    passed = sum(ok for _, ok in results)
    print(f'\n{passed}/{len(results)} passed')
    sys.exit(0 if passed == len(results) else 1)


if __name__ == '__main__':
    main()
