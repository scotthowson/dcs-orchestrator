#!/usr/bin/env python3
"""A stand-in for the parts of Cloudflare's API that "Push bans to Cloudflare" uses, plus a stand-in for CrowdSec's
local API (GET /v1/decisions), for tests. Nothing here reaches a network: it listens on 127.0.0.1 only.

    mock-cloudflare-waf.py PORT_FILE STATE_FILE [CROWDSEC_STATE_JSON]

Cloudflare (under /client/v4, Bearer token):
    GET  /user/tokens/verify                                  a user token: {status}; an account-owned token: 401 (1000)
    GET  /accounts/{a}/tokens/verify                          an account-owned token of that account
    GET  /zones?name=                                         right "zones"
    GET|POST /accounts/{a}/rules/lists, DELETE …/{id}          right "lists"; one list on a free account (max_lists), a referenced list is not deleted
    GET|PUT  /accounts/{a}/rules/lists/{id}/items             PUT replaces all items (a bulk operation); max_items over all lists
    GET  /accounts/{a}/rules/lists/bulk_operations/{op}
    GET|PUT  /zones/{z}/rulesets/phases/http_request_firewall_custom/entrypoint   right "waf"; 404 while the zone has none
    POST /zones/{z}/rulesets/{rs}/rules, PATCH|DELETE …/{rid}  max_rules per zone; an expression must name a list of the zone's account
CrowdSec's local API (X-Api-Key, checked against the bouncers of the mock-crowdsec state when it is given, else against "lapi_keys"):
    GET  /v1/decisions?type=&scopes=&origins=                 the decisions set with POST /_mock/decisions ("null" when none, like CrowdSec)
Control (no auth): POST /_mock/config {…merged into the configuration}, POST /_mock/decisions [...], GET /_mock/state.
Every request is appended to state["calls"] as "METHOD path" (the Authorization and X-Api-Key headers are kept apart, in
state["auth_seen"], so a test can say which token reached the API)."""
import http.server, json, sys, urllib.parse, pathlib, itertools, threading, ipaddress

PORTF, STATEF = sys.argv[1], pathlib.Path(sys.argv[2])
CS_STATE = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 else None
LOCK = threading.Lock()
SEQ = itertools.count(1)
PHASE = 'http_request_firewall_custom'

S = {
    'config': {
        # token -> {kind: user|account, account: id, status: active|disabled|expired, rights: [zones, lists, waf]}
        'tokens': {},
        'zones': [],                # [{id, name, account: {id, name}, plan: free|pro|…}]
        'max_lists': 1, 'max_items': 10000, 'max_rules': 5,
        'bulk_steps': 1,            # how many polls a bulk operation stays "running"
        'lapi_keys': [], 'lapi_down': False,
    },
    'lists': {},                    # account -> [{id, name, kind, description, items: [{id, ip, comment}]}]
    'rulesets': {},                 # zone -> {id, phase, rules: [{id, ref, expression, action, enabled, description}]}
    'ops': {},                      # op id -> {status, polls, error}
    'decisions': [],
    'calls': [], 'auth_seen': [], 'lapi_pulls': 0,
}


def save():
    STATEF.write_text(json.dumps(S, indent=1))


def env(code, result=None, errors=None, info=None):
    o = {'success': not errors and code < 400, 'errors': errors or [], 'messages': [], 'result': result}
    if info is not None:
        o['result_info'] = info
    return code, o


def err(code, ecode, msg):
    return env(code, None, [{'code': ecode, 'message': msg}])


def hexid():
    return '%032x' % (next(SEQ) * 7919 + 0xabc)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = (json.dumps(obj) if not isinstance(obj, (bytes, str)) else obj)
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(n) if n else b''
        try:
            return json.loads(raw or b'null')
        except ValueError:
            return '__bad__'

    def _route(self, method):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        p = u.path
        body = self._body() if method in ('POST', 'PUT', 'PATCH', 'DELETE') else None
        with LOCK:
            if p.startswith('/_mock/'):
                return self._control(method, p, body)
            S['calls'].append('%s %s' % (method, self.path))
            if p.startswith('/v1/'):
                return self._lapi(method, p, q)
            auth = self.headers.get('Authorization', '')
            S['auth_seen'].append(auth[7:] if auth.startswith('Bearer ') else '(none)')
            code, obj = self._cf(method, p, q, body, auth[7:] if auth.startswith('Bearer ') else '')
            save()
            self._send(code, obj)

    def do_GET(self): self._route('GET')
    def do_POST(self): self._route('POST')
    def do_PUT(self): self._route('PUT')
    def do_PATCH(self): self._route('PATCH')
    def do_DELETE(self): self._route('DELETE')

    # ---- control --------------------------------------------------------------------------------------------
    def _control(self, method, p, body):
        if p == '/_mock/config' and method == 'POST' and isinstance(body, dict):
            S['config'].update(body); save(); return self._send(200, S['config'])
        if p == '/_mock/decisions' and method == 'POST' and isinstance(body, list):
            S['decisions'] = body; save(); return self._send(200, {'n': len(body)})
        if p == '/_mock/reset' and method == 'POST':
            S['lists'] = {}; S['rulesets'] = {}; S['ops'] = {}; S['calls'] = []; S['auth_seen'] = []; S['lapi_pulls'] = 0; save(); return self._send(200, {})
        if p == '/_mock/state':
            return self._send(200, S)
        return self._send(404, {'error': 'no such control'})

    # ---- CrowdSec's local API ------------------------------------------------------------------------------
    def _lapi_keys(self):
        keys = list(S['config'].get('lapi_keys') or [])
        if CS_STATE and CS_STATE.exists():
            try:
                st = json.loads(CS_STATE.read_text())
                keys += [b.get('key') for b in st.get('cs', {}).get('bouncers', []) if b.get('key') and not b.get('revoked')]
            except (OSError, ValueError):
                pass
        return keys

    def _lapi(self, method, p, q):
        if S['config'].get('lapi_down'):
            # like a CrowdSec that is not running: the connection ends without an answer
            self.close_connection = True
            return
        key = self.headers.get('X-Api-Key', '')
        if S['config'].get('lapi_refuse_all') or key not in self._lapi_keys():
            return self._send(403, {'message': 'access forbidden'})
        if p != '/v1/decisions' or method != 'GET':
            return self._send(404, {'message': 'page not found'})
        S['lapi_pulls'] += 1
        rows = S['decisions']
        if 'type' in q:
            rows = [r for r in rows if r.get('type', 'ban') == q['type'][0]]
        if 'scopes' in q:
            want = {s.lower() for s in q['scopes'][0].split(',')}
            rows = [r for r in rows if r.get('scope', 'Ip').lower() in want]
        if 'origins' in q:
            want = set(q['origins'][0].split(','))
            rows = [r for r in rows if r.get('origin', 'crowdsec') in want]
        out = [{'id': r.get('id', i + 1), 'origin': r.get('origin', 'crowdsec'), 'scope': r.get('scope', 'Ip'), 'value': r['value'],
                'type': r.get('type', 'ban'), 'scenario': r.get('scenario', 'crowdsecurity/http-probing'), 'duration': '3h59m'} for i, r in enumerate(rows)]
        if 'limit' in q:
            out = out[:int(q['limit'][0])]
        save()
        return self._send(200, json.dumps(out) if out else 'null')

    # ---- Cloudflare -----------------------------------------------------------------------------------------
    def _tok(self, t):
        return S['config']['tokens'].get(t)

    def _need(self, tok, right):
        return tok is not None and tok.get('status', 'active') == 'active' and right in (tok.get('rights') or [])

    def _zone(self, zid):
        return next((z for z in S['config']['zones'] if z['id'] == zid), None)

    def _list_names(self, acc):
        return {l['name'] for l in S['lists'].get(acc, [])}

    def _cf(self, method, p, q, body, token):
        if not p.startswith('/client/v4/'):
            return err(404, 7003, 'No route for that URI')
        parts = p[len('/client/v4/'):].strip('/').split('/')
        tok = self._tok(token)
        if tok is None:
            return err(401 if parts[:3] == ['user', 'tokens', 'verify'] else 400, 1000 if parts[:3] == ['user', 'tokens', 'verify'] else 6003,
                       'Invalid API Token' if parts[:3] == ['user', 'tokens', 'verify'] else 'Invalid request headers')
        # -- tokens
        if parts == ['user', 'tokens', 'verify']:
            if tok.get('kind', 'user') != 'user':
                return err(401, 1000, 'Invalid API Token')
            return env(200, {'id': 'tok-1', 'status': tok.get('status', 'active')})
        if len(parts) == 4 and parts[0] == 'accounts' and parts[2:] == ['tokens', 'verify']:
            if tok.get('kind') != 'account' or tok.get('account') != parts[1]:
                return err(401, 1000, 'Invalid API Token')
            return env(200, {'id': 'tok-2', 'status': tok.get('status', 'active')})
        if tok.get('status', 'active') != 'active':
            return err(403, 9109, 'Unauthorized to access requested resource')
        # -- zones
        if parts == ['zones'] and method == 'GET':
            if not self._need(tok, 'zones'):
                return err(403, 9109, 'Unauthorized to access requested resource')
            name = q.get('name', [''])[0]
            res = [z for z in S['config']['zones'] if (not name or z['name'] == name)]
            res = [{'id': z['id'], 'name': z['name'], 'status': 'active', 'account': z['account'], 'plan': {'name': z.get('plan', 'free').title() + ' Website', 'legacy_id': z.get('plan', 'free')}} for z in res]
            return env(200, res, info={'count': len(res), 'total_count': len(res), 'page': 1, 'per_page': 20})
        # -- lists
        if len(parts) >= 4 and parts[0] == 'accounts' and parts[2:4] == ['rules', 'lists']:
            acc = parts[1]
            if not any(z['account']['id'] == acc for z in S['config']['zones']):
                return err(403, 10000, 'Authentication error')
            if not self._need(tok, 'lists'):
                return err(403, 10000, 'Authentication error')
            lists = S['lists'].setdefault(acc, [])
            rest = parts[4:]
            if not rest:
                if method == 'GET':
                    return env(200, [self._list_out(l) for l in lists])
                if method == 'POST':
                    if not isinstance(body, dict) or not body.get('name') or body.get('kind') != 'ip':
                        return err(400, 10026, 'filter list name and kind are required')
                    if body['name'] in self._list_names(acc):
                        return err(400, 10014, 'duplicate list name')
                    if len(lists) >= S['config']['max_lists']:
                        return err(400, 10027, 'exceeded maximum number of lists')
                    l = {'id': hexid(), 'name': body['name'], 'kind': 'ip', 'description': body.get('description', ''), 'items': []}
                    lists.append(l)
                    return env(200, self._list_out(l))
            if rest[0] == 'bulk_operations' and len(rest) == 2 and method == 'GET':
                op = S['ops'].get(rest[1])
                if not op:
                    return err(404, 10001, 'operation not found')
                op['polls'] += 1
                if op['polls'] < S['config'].get('bulk_steps', 1):
                    return env(200, {'id': rest[1], 'status': 'running'})
                if op.get('error'):
                    return env(200, {'id': rest[1], 'status': 'failed', 'error': op['error'], 'completed': '2026-10-09T12:00:00Z'})
                return env(200, {'id': rest[1], 'status': 'completed', 'completed': '2026-10-09T12:00:00Z'})
            l = next((x for x in lists if x['id'] == rest[0]), None)
            if not l:
                return err(404, 10001, 'list not found')
            if len(rest) == 1 and method == 'DELETE':
                ref = any(('$' + l['name']) in r['expression'] for rs in S['rulesets'].values() for r in rs['rules'])
                if ref:
                    return err(400, 10017, 'list is referenced by one or more filters')
                lists.remove(l)
                return env(200, {'id': l['id']})
            if len(rest) == 2 and rest[1] == 'items':
                if method == 'GET':
                    return env(200, [{'id': i['id'], 'ip': i['ip'], 'comment': i.get('comment', '')} for i in l['items']], info={'cursors': {}})
                if method == 'PUT':
                    # Cloudflare's "slow down": the next ratelimit_puts replacements are refused, as an HTTP 429 or as a failed bulk operation
                    if S['config'].get('ratelimit_puts', 0) > 0:
                        S['config']['ratelimit_puts'] -= 1
                        if S['config'].get('ratelimit_mode', 'http') == 'http':
                            return err(429, 971, 'you have been ratelimited please wait and try again')
                        op = hexid(); S['ops'][op] = {'polls': 0, 'error': 'you have been ratelimited please wait and try again'}
                        return env(200, {'operation_id': op})
                    if not isinstance(body, list):
                        return err(400, 10026, 'the body must be an array of items')
                    for it in body:
                        try:
                            ip = it['ip']
                            net = ipaddress.ip_network(ip, strict=False)
                            if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 12):
                                raise ValueError
                        except (KeyError, ValueError, TypeError):
                            return err(400, 10021, 'invalid ip in list item: %r' % (it,))
                    others = sum(len(x['items']) for a, ls in S['lists'].items() for x in ls if x is not l)
                    op = hexid()
                    if others + len(body) > S['config']['max_items']:
                        S['ops'][op] = {'polls': 0, 'error': 'This list is at the maximum number of items'}
                    else:
                        l['items'] = [{'id': hexid(), 'ip': it['ip'], 'comment': it.get('comment', '')} for it in body]
                        S['ops'][op] = {'polls': 0}
                    return env(200, {'operation_id': op})
            return err(405, 10000, 'method not allowed')
        # -- rulesets
        if len(parts) >= 3 and parts[0] == 'zones' and parts[2] == 'rulesets':
            z = self._zone(parts[1])
            if not z:
                return err(403, 10000, 'Authentication error')
            if not self._need(tok, 'waf'):
                return err(403, 10000, 'Authentication error')
            rs = S['rulesets'].get(z['id'])
            rest = parts[3:]
            if rest == ['phases', PHASE, 'entrypoint']:
                if method == 'GET':
                    if not rs:
                        return err(404, 10003, 'could not find entrypoint ruleset in the %s phase' % PHASE)
                    return env(200, rs)
                if method == 'PUT':
                    rules = (body or {}).get('rules') or []
                    if len(rules) > S['config']['max_rules']:
                        return err(400, 20217, 'exceeded maximum number of rules in the phase')
                    for r in rules:
                        bad = self._bad_rule(z, r)
                        if bad:
                            return err(400, 20200, bad)
                    rs = {'id': hexid(), 'name': 'default', 'kind': 'zone', 'phase': PHASE, 'version': '1', 'rules': [self._rule_in(r) for r in rules]}
                    S['rulesets'][z['id']] = rs
                    return env(200, rs)
            if len(rest) >= 2 and rs and rest[0] == rs['id'] and rest[1] == 'rules':
                if len(rest) == 2 and method == 'POST':
                    if len(rs['rules']) >= S['config']['max_rules']:
                        return err(400, 20217, 'exceeded maximum number of rules in the phase')
                    bad = self._bad_rule(z, body or {})
                    if bad:
                        return err(400, 20200, bad)
                    r = self._rule_in(body)
                    pos = (body or {}).get('position') or {}
                    idx = pos.get('index')
                    if isinstance(idx, int) and idx >= 1:
                        rs['rules'].insert(idx - 1, r)
                    else:
                        rs['rules'].append(r)
                    return env(200, rs)
                if len(rest) == 3:
                    r = next((x for x in rs['rules'] if x['id'] == rest[2]), None)
                    if not r:
                        return err(404, 10001, 'rule not found')
                    if method == 'DELETE':
                        rs['rules'].remove(r)
                        return env(200, rs)
                    if method == 'PATCH':
                        bad = self._bad_rule(z, body or {})
                        if bad:
                            return err(400, 20200, bad)
                        r.update({k: v for k, v in (body or {}).items() if k in ('expression', 'action', 'enabled', 'description', 'ref')})
                        return env(200, rs)
            return err(404, 10001, 'ruleset not found')
        return err(404, 7003, 'No route for that URI')

    def _bad_rule(self, z, r):
        if r.get('action') not in ('block', 'managed_challenge', 'skip', 'log', 'js_challenge', 'challenge'):
            return 'invalid action'
        expr = r.get('expression') or ''
        for word in expr.split():
            if word.startswith('$') and word.strip('()$') not in self._list_names(z['account']['id']):
                return "filter parsing error: could not find list '%s'" % word.strip('()$')
        return ''

    def _rule_in(self, r):
        return {'id': hexid(), 'version': '1', 'ref': r.get('ref') or '', 'expression': r.get('expression', ''), 'action': r.get('action'),
                'enabled': r.get('enabled', True), 'description': r.get('description', ''), 'last_updated': '2026-10-09T12:00:00Z'}

    def _list_out(self, l):
        refs = sum(1 for rs in S['rulesets'].values() for r in rs['rules'] if ('$' + l['name']) in r['expression'])
        return {'id': l['id'], 'name': l['name'], 'kind': l['kind'], 'description': l['description'], 'num_items': len(l['items']),
                'num_referencing_filters': refs, 'created_on': '2026-10-09T12:00:00Z', 'modified_on': '2026-10-09T12:00:00Z'}


if STATEF.exists():
    try:
        S.update(json.loads(STATEF.read_text()))
    except ValueError:
        pass
srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
save()
pathlib.Path(PORTF).write_text(str(srv.server_address[1]))
srv.serve_forever()
