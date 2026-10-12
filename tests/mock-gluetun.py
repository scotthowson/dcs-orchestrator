#!/usr/bin/env python3
"""Stand-ins for tests/smoke.sh's VPN section, on one port: Gluetun's control server (X-API-Key), qBittorrent's
web API (/api/v2, a login when "qbit_auth" is on) and Private Internet Access (the token, the server list, addKey).

  mock-gluetun.py PORTFILE STATEFILE APIKEY

STATEFILE is JSON the test edits and reads back: {"vpn": "running", "public_ip": "...", "country": "...", "port": N,
"qbit_auth": false, "qbit_user": "...", "qbit_pass": "...", "pia_user": "...", "pia_pass": "...", "calls": [[method, path,
has_key, secret_in_url]], "qbit_prefs": {...}, "addkey": [{pt, pubkey}]}.
"""
import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORTFILE, STATE, KEY = sys.argv[1], sys.argv[2], sys.argv[3]
DEFAULT = {"vpn": "running", "public_ip": "198.51.100.7", "country": "Canada", "region": "Quebec", "city": "Montreal",
           "port": 41234, "qbit_auth": False, "qbit_user": "admin", "qbit_pass": "qb-secret-pass", "pia_user": "p1234567",
           "pia_pass": "pia-secret-pass", "calls": [], "qbit_prefs": {}, "addkey": []}


def load():
    try:
        with open(STATE) as f:
            return {**DEFAULT, **json.load(f)}
    except (OSError, ValueError):
        return dict(DEFAULT)


def save(s):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f)
    os.replace(tmp, STATE)


SERVERLIST = {"regions": [
    {"id": "us_east", "name": "US East", "country": "US", "port_forward": False, "geo": False,
     "servers": {"meta": [{"ip": "127.0.0.1", "cn": "useast1"}], "wg": [{"ip": "127.0.0.1", "cn": "useast401"}]}},
    {"id": "swiss", "name": "Switzerland", "country": "CH", "port_forward": True, "geo": False,
     "servers": {"meta": [{"ip": "127.0.0.2", "cn": "swiss1"}], "wg": [{"ip": "127.0.0.1", "cn": "zurich401"}]}},
    {"id": "ca_toronto", "name": "CA Toronto", "country": "CA", "port_forward": True, "geo": False,
     "servers": {"meta": [{"ip": "127.0.0.1", "cn": "toronto1"}], "wg": [{"ip": "127.0.0.1", "cn": "toronto421"}]}},
    {"id": "ca", "name": "CA Montreal", "country": "CA", "port_forward": True, "geo": False,
     "servers": {"meta": [{"ip": "127.0.0.1", "cn": "montreal1"}], "wg": [{"ip": "127.0.0.1", "cn": "montreal424"}]}}]}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", headers=()):
        b = body if isinstance(body, bytes) else (json.dumps(body) if not isinstance(body, str) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode() if n else ""

    def handle_any(self, method):
        s = load()
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        raw = self.body()
        secrets = [s["qbit_pass"], s["pia_pass"], KEY]
        s["calls"].append([method, u.path, self.headers.get("X-API-Key") == KEY, any(x in self.path for x in secrets)])
        save(s)
        p = u.path
        # Gluetun's control server
        if p.startswith("/v1/"):
            if self.headers.get("X-API-Key") != KEY:
                return self.send(401, {"error": "unauthorized"})
            if p == "/v1/vpn/status":
                return self.send(200, {"status": s["vpn"]})
            if p == "/v1/publicip/ip":
                if s["vpn"] != "running":
                    return self.send(200, {"public_ip": ""})
                return self.send(200, {"public_ip": s["public_ip"], "country": s["country"], "region": s["region"], "city": s["city"]})
            if p == "/v1/portforward":
                return self.send(200, {"port": s["port"] if s["vpn"] == "running" else 0})
            return self.send(404, {"error": "no route"})
        # qBittorrent
        if p == "/api/v2/auth/login":
            f = urllib.parse.parse_qs(raw)
            if f.get("username") == [s["qbit_user"]] and f.get("password") == [s["qbit_pass"]]:
                return self.send(200, "Ok.", "text/plain", [("Set-Cookie", "SID=mocksid; HttpOnly; path=/")])
            return self.send(200, "Fails.", "text/plain")
        if p == "/api/v2/app/setPreferences":
            if s["qbit_auth"] and "SID=mocksid" not in (self.headers.get("Cookie") or ""):
                return self.send(403, "Forbidden", "text/plain")
            f = urllib.parse.parse_qs(raw)
            s = load()
            s["qbit_prefs"] = json.loads(f["json"][0])
            save(s)
            return self.send(200, "", "text/plain")
        # what the outside sees of the machine itself (VPN_IP_ECHO_URL in the test)
        if p == "/myip":
            return self.send(200, s.get("home_ip", "192.0.2.50") + "\n", "text/plain")
        # PIA
        if p == "/pia/token":
            f = self.headers.get("Content-Type", "")
            ok = s["pia_user"] in raw and s["pia_pass"] in raw and "multipart/form-data" in f
            return self.send(200 if ok else 401, {"token": "mocktoken0123456789"} if ok else {"message": "bad"})
        if p == "/pia/servers":
            return self.send(200, json.dumps(SERVERLIST) + "\n\nSIGNATURE", "text/plain")
        if p == "/pia/addKey":
            s = load()
            s["addkey"].append({"pt": q.get("pt", [""])[0], "pubkey": q.get("pubkey", [""])[0]})
            save(s)
            if q.get("pt") != ["mocktoken0123456789"] or len(q.get("pubkey", [""])[0]) != 44:
                return self.send(200, {"status": "ERROR"})
            return self.send(200, {"status": "OK", "server_key": "c2VydmVyLWtleS0wMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                                   "server_port": 1337, "server_ip": "203.0.113.10", "server_vip": "10.1.0.1",
                                   "peer_ip": "10.1.2.3", "peer_pubkey": q["pubkey"][0], "dns_servers": ["10.0.0.243"]})
        return self.send(404, {"error": "unknown"})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
save(load())
with open(PORTFILE + ".tmp", "w") as f:
    f.write(str(srv.server_address[1]))
os.replace(PORTFILE + ".tmp", PORTFILE)
srv.serve_forever()
