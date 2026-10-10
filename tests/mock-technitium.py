#!/usr/bin/env python3
"""A stand-in for one Technitium DNS Server's HTTP API (the calls .lib/technitium.sh makes), for tests/smoke.sh.

Usage: mock-technitium.py PORTFILE STATEFILE TOKEN NAME
  binds 127.0.0.1 on a free port and writes it to PORTFILE; keeps its state in STATEFILE (JSON, rewritten after
  every call, so the test reads what landed); TOKEN is the API token it accepts (Authorization: Bearer, as v15 wants);
  NAME is its dnsServerDomain. Every request is logged in the state's "calls" ([path, had_bearer, token_in_url]).
"""
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORTFILE, STATEFILE, TOKEN, NAME = sys.argv[1:5]
STORE = [
    {"name": "Advanced Blocking", "version": "11.2.1", "url": "https://download.technitium.com/dns/apps/AdvancedBlockingApp-v11.2.1.zip"},
    {"name": "Query Logs (Sqlite)", "version": "9.1.2", "url": "https://download.technitium.com/dns/apps/QueryLogsSqliteApp-v9.1.2.zip"},
]
DEFAULT_CONFIG = {
    "Advanced Blocking": {"enableBlocking": True, "networkGroupMap": {"0.0.0.0/0": "everyone else"},
                          "groups": [{"name": "everyone else", "blockListUrls": ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]}]},
    "Query Logs (Sqlite)": {"enableLogging": True, "maxQueueSize": 200000, "maxLogDays": 7, "maxLogRecords": 10000, "sqliteDbPath": "querylogs.db"},
}
ARRAYS = {"forwarders", "blockListUrls"}
INTS = {"forwarderConcurrency", "blockListUpdateIntervalHours", "cacheMaximumEntries"}
BOOLS = {"dnssecValidation", "preferIPv6", "concurrentForwarding", "serveStale", "enableBlocking"}

state = {
    "settings": {"version": "15.6", "uptimestamp": "2026-10-01T08:00:00.0000000Z", "dnsServerDomain": NAME, "enableBlocking": True,
                 "temporaryDisableBlockingTill": None, "forwarders": None, "forwarderProtocol": "Udp", "forwarderConcurrency": 2,
                 "concurrentForwarding": True, "dnssecValidation": True, "preferIPv6": False, "blockListUrls": None,
                 "blockListUpdateIntervalHours": 24, "blockListNextUpdatedOn": "2026-10-10T08:00:00.000Z", "cacheMaximumEntries": 10000,
                 "serveStale": True, "blockingType": "NxDomain"},
    "apps": {}, "allowed": [], "blocked": [], "zones": {}, "calls": [],
}


def save():
    with open(STATEFILE + ".tmp", "w") as f:
        json.dump(state, f, indent=1)
    os.replace(STATEFILE + ".tmp", STATEFILE)


def stats(n):
    """canned numbers, different per server so a merge shows"""
    k = 2 if NAME == "dns1" else 1
    labels = [(datetime(2026, 10, 10, 8, 0, tzinfo=timezone.utc) + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:00.0000000Z") for i in range(3)]
    return {"stats": {"totalQueries": 100 * k, "totalBlocked": 10 * k, "totalClients": 3, "totalCached": 40, "totalNxDomain": 5},
            "mainChartData": {"labels": labels, "datasets": [{"label": "Total", "data": [10 * k, 20 * k, 70 * k]}, {"label": "Blocked", "data": [1, 2, 10 * k - 3]}]},
            "topClients": [{"name": "192.168.2.50", "domain": "tablet-9.home", "hits": 60 * k}, {"name": "192.168.2.10", "hits": 30 * k}],
            "topDomains": [{"name": "example.com", "hits": 50 * k}, {"name": "youtube.com", "hits": 20}],
            "topBlockedDomains": [{"name": "ads.example.net", "hits": 7 * k}],
            "queryTypeChartData": {"labels": ["A", "AAAA"], "datasets": [{"data": [80 * k, 20 * k]}]}}


LOGS = [
    {"timestamp": "2026-10-10T08:01:00Z", "clientIpAddress": "192.168.2.50", "responseType": "Recursive", "rcode": "NoError", "qname": "example.com", "qtype": "A", "answer": "93.184.215.14"},
    {"timestamp": "2026-10-10T08:02:00Z", "clientIpAddress": "192.168.2.50", "responseType": "Blocked", "rcode": "NxDomain", "qname": "ads.example.net", "qtype": "A", "answer": ""},
    {"timestamp": "2026-10-10T08:03:00Z", "clientIpAddress": "192.168.2.10", "responseType": "Cached", "rcode": "NoError", "qname": "dcs.example.org", "qtype": "AAAA", "answer": ""},
]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def answer(self, obj, text=None):
        body = (text if text is not None else json.dumps(obj)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain" if text is not None else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.handle_call(b"")

    def do_POST(self):
        self.handle_call(self.rfile.read(int(self.headers.get("Content-Length") or 0)))

    def handle_call(self, raw):
        u = urlsplit(self.path)
        q = {k: v[-1] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        q.update({k: v[-1] for k, v in parse_qs(raw.decode(), keep_blank_values=True).items()})
        auth = self.headers.get("Authorization", "")
        state["calls"].append([u.path, auth.startswith("Bearer "), TOKEN in self.path])
        if auth != "Bearer " + TOKEN:
            save()
            return self.answer({"status": "invalid-token", "errorMessage": "Invalid token or session expired."})
        try:
            r = self.route(u.path, q)
        except Exception as e:  # what Technitium does with a bad parameter
            r = {"status": "error", "errorMessage": str(e)}
        save()
        if isinstance(r, str):
            return self.answer(None, r)
        return self.answer(r)

    def route(self, p, q):
        s = state["settings"]
        ok = lambda resp=None: {"response": resp or {}, "server": NAME, "status": "ok"}
        if p == "/api/settings/get":
            return ok(s)
        if p == "/api/settings/set":
            for k, v in q.items():
                if k in ARRAYS:
                    s[k] = [] if v == "false" else [x for x in v.split(",") if x]
                elif k in INTS:
                    s[k] = int(v)
                elif k in BOOLS:
                    s[k] = v == "true"
                else:
                    s[k] = v
                if k == "enableBlocking" and v == "true":
                    s["temporaryDisableBlockingTill"] = None
            return ok(s)
        if p == "/api/settings/temporaryDisableBlocking":
            till = (datetime.now(timezone.utc) + timedelta(minutes=int(q["minutes"]))).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
            s["enableBlocking"] = False
            s["temporaryDisableBlockingTill"] = till
            return ok({"temporaryDisableBlockingTill": till})
        if p == "/api/dashboard/stats/get":
            return ok(stats(q.get("type")))
        if p == "/api/apps/list":
            return ok({"apps": [{"name": n, "version": "1", "dnsApps": []} for n in state["apps"]]})
        if p == "/api/apps/listStoreApps":
            return ok({"storeApps": [dict(a, installed=a["name"] in state["apps"]) for a in STORE]})
        if p == "/api/apps/downloadAndInstall":
            if not q.get("url", "").startswith("https://"):
                raise ValueError("url must start with https://")
            state["apps"][q["name"]] = json.dumps(DEFAULT_CONFIG.get(q["name"], {}))
            return ok({"installedApp": {"name": q["name"]}})
        if p == "/api/apps/config/get":
            if q["name"] not in state["apps"]:
                raise ValueError("DNS application was not found: " + q["name"])
            return ok({"config": state["apps"][q["name"]]})
        if p == "/api/apps/config/set":
            json.loads(q["config"])
            state["apps"][q["name"]] = q["config"]
            return ok()
        for zone in ("allowed", "blocked"):
            if p == f"/api/{zone}/add":
                if q["domain"] not in state[zone]:
                    state[zone].append(q["domain"])
                return ok()
            if p == f"/api/{zone}/delete":
                state[zone] = [d for d in state[zone] if d != q["domain"]]
                return ok()
            if p == f"/api/{zone}/import":
                for d in q[zone + "Zones"].split(","):
                    if d and d not in state[zone]:
                        state[zone].append(d)
                return ok()
            if p == f"/api/{zone}/export":
                return "".join(d + "\r\n" for d in state[zone])
        if p == "/api/logs/query":
            if q.get("name") not in state["apps"]:
                raise ValueError("DNS application was not found: " + str(q.get("name")))
            e = [x for x in LOGS if not q.get("clientIpAddress") or x["clientIpAddress"] == q["clientIpAddress"]]
            if q.get("responseType"):
                e = [x for x in e if x["responseType"] == q["responseType"]]
            if q.get("qname"):
                needle = q["qname"].replace("*", "")
                e = [x for x in e if needle in x["qname"]]
            e = sorted(e, key=lambda x: x["timestamp"], reverse=True)[: int(q.get("entriesPerPage", 25))]
            return ok({"pageNumber": 1, "totalPages": 1, "totalEntries": len(e), "entries": e})
        if p == "/api/zones/list":
            return ok({"zones": [{"name": n, "type": z["type"], "internal": False} for n, z in state["zones"].items()]
                       + [{"name": "localhost", "type": "Primary", "internal": True}]})
        if p == "/api/zones/create":
            if q["zone"] in state["zones"]:
                raise ValueError("Zone already exists: " + q["zone"])
            state["zones"][q["zone"]] = {"type": q["type"], "records": []}
            return ok({"domain": q["zone"]})
        if p == "/api/zones/delete":
            if q["zone"] not in state["zones"]:
                raise ValueError("No such zone was found: " + q["zone"])
            del state["zones"][q["zone"]]
            return ok()
        if p == "/api/zones/records/get":
            z = state["zones"][q["zone"]]
            return ok({"zone": {"name": q["zone"], "type": z["type"]}, "records": z["records"]})
        if p == "/api/zones/records/add":
            z = state["zones"][q["zone"]]
            if q["type"] == "CNAME" and q["domain"] == q["zone"]:
                raise ValueError("Cannot set CNAME record at zone apex.")
            z["records"].append({"name": q["domain"], "type": q["type"], "ttl": int(q.get("ttl", 3600)), "rData": {"aname": q.get("aname")}})
            return ok()
        raise ValueError("Invalid API call: " + p)


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
save()
with open(PORTFILE + ".tmp", "w") as f:
    f.write(str(srv.server_address[1]))
os.replace(PORTFILE + ".tmp", PORTFILE)
srv.serve_forever()
