#!/usr/bin/env python3
"""A stand-in for one Technitium DNS Server's HTTP API (the calls .lib/technitium.sh makes), for tests/smoke.sh.

Usage: mock-technitium.py PORTFILE STATEFILE TOKEN NAME
  binds 127.0.0.1 on a free port and writes it to PORTFILE; keeps its state in STATEFILE (JSON, rewritten after
  every call, so the test reads what landed); TOKEN is the API token it accepts (Authorization: Bearer, as v15 wants);
  NAME is its dnsServerDomain. Every request is logged in the state's "calls" ([path, had_bearer, token_in_url]).
  DHCP behaves as Technitium 15's does: a stock "Default" scope that is off, a scope made by scopes/set is on at once (renaming
  one with newName keeps it as it was), a reservation is not a lease, a MAC is reserved once a scope. A lease is put in with
  the stand-in's own POST /api/_mock/lease {scope, hardwareAddress, address, hostName} (the token is needed as for any call).
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
    "dhcp": {"scopes": {"Default": {"enabled": False, "startingAddress": "192.168.1.1", "endingAddress": "192.168.1.254", "subnetMask": "255.255.255.0",
                                    "leaseTimeDays": 1, "leaseTimeHours": 0, "leaseTimeMinutes": 0, "domainName": "home", "routerAddress": "192.168.1.1",
                                    "useThisDnsServer": True, "dnsServers": [], "exclusions": [{"startingAddress": "192.168.1.1", "endingAddress": "192.168.1.10"}],
                                    "reservedLeases": []}},
             "leases": []},
}
# who asked over the last day (the top clients), and the names reverse DNS knows
TOP = {"dns1": [{"name": "192.168.2.50", "domain": "tablet-9.home", "hits": 120}, {"name": "192.168.2.60", "hits": 40}, {"name": "192.168.2.77", "hits": 5},
                {"name": "127.0.0.1", "hits": 9}, {"name": "fd00::5", "hits": 3}],
       "dns2": [{"name": "192.168.2.50", "domain": "tablet-9.home", "hits": 30}]}
PTR = {"70.2.168.192.in-addr.arpa": "pi-hole.home"}


def ip2n(a):
    p = [int(x) for x in a.split(".")]
    if len(p) != 4 or any(x < 0 or x > 255 for x in p):
        raise ValueError("An invalid IP address was specified.")
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]


def n2ip(n):
    return ".".join(str((n >> s) & 255) for s in (24, 16, 8, 0))


def scope_view(name, sc, full):
    m = ip2n(sc["subnetMask"])
    net = ip2n(sc["startingAddress"]) & m
    v = {"name": name, "enabled": sc["enabled"], "startingAddress": sc["startingAddress"], "endingAddress": sc["endingAddress"],
         "subnetMask": sc["subnetMask"], "networkAddress": n2ip(net), "broadcastAddress": n2ip(net | (~m & 0xFFFFFFFF))}
    if full:
        v = dict(sc, name=name)
        v.pop("enabled", None)
    return v


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
        if p == "/api/dashboard/stats/getTop":
            return ok({"topClients": TOP.get(NAME, [])[: int(q.get("limit", 1000))]})
        if p == "/api/dnsClient/resolve":
            ans = [{"Name": q["domain"], "Type": "PTR", "RDATA": {"Domain": PTR[q["domain"]]}}] if q.get("type") == "PTR" and q.get("domain") in PTR else []
            return ok({"result": {"Answer": ans}})
        d = state["dhcp"]
        if p == "/api/dhcp/scopes/list":
            return ok({"scopes": [scope_view(n, sc, False) for n, sc in d["scopes"].items()]})
        if p == "/api/dhcp/scopes/get":
            if q["name"] not in d["scopes"]:
                raise ValueError("DHCP scope was not found: " + q["name"])
            return ok(scope_view(q["name"], d["scopes"][q["name"]], True))
        if p == "/api/dhcp/scopes/set":
            new = q["name"] not in d["scopes"]
            sc = d["scopes"].get(q["name"]) or {"enabled": True, "leaseTimeDays": 1, "leaseTimeHours": 0, "leaseTimeMinutes": 0, "domainName": "",
                                                "routerAddress": None, "useThisDnsServer": True, "dnsServers": [], "exclusions": [], "reservedLeases": []}
            for k in ("startingAddress", "endingAddress", "subnetMask", "routerAddress"):
                if k in q:
                    ip2n(q[k])
                    sc[k] = q[k]
            for k in ("leaseTimeDays", "leaseTimeHours", "leaseTimeMinutes"):
                if k in q:
                    sc[k] = int(q[k])
            if "domainName" in q:
                sc["domainName"] = q["domainName"]
            if "pingCheckEnabled" in q:
                sc["pingCheckEnabled"] = q["pingCheckEnabled"] == "true"
            if "useThisDnsServer" in q:
                sc["useThisDnsServer"] = q["useThisDnsServer"] == "true"
            if "dnsServers" in q:
                sc["dnsServers"] = [x for x in q["dnsServers"].split(",") if x and ip2n(x) is not None]
            if "exclusions" in q:
                x = [e for e in q["exclusions"].split("|") if e]
                for e in x:
                    ip2n(e)
                sc["exclusions"] = [{"startingAddress": x[i], "endingAddress": x[i + 1]} for i in range(0, len(x) - 1, 2)]
            if new and "startingAddress" not in q:
                raise ValueError("Parameter 'startingAddress' missing.")
            name = q.get("newName") or q["name"]
            d["scopes"].pop(q["name"], None)
            d["scopes"][name] = sc
            return ok()
        if p in ("/api/dhcp/scopes/enable", "/api/dhcp/scopes/disable"):
            if q["name"] not in d["scopes"]:
                raise ValueError("DHCP scope was not found: " + q["name"])
            d["scopes"][q["name"]]["enabled"] = p.endswith("/enable")
            return ok()
        if p == "/api/dhcp/scopes/addReservedLease":
            sc = d["scopes"][q["name"]]
            if any(r["hardwareAddress"] == q["hardwareAddress"] for r in sc["reservedLeases"]):
                raise ValueError("A reserved lease with same hardware address already exists in scope: " + q["name"])
            ip2n(q["ipAddress"])
            sc["reservedLeases"].append({"hostName": q.get("hostName"), "hardwareAddress": q["hardwareAddress"], "address": q["ipAddress"], "comments": q.get("comments")})
            return ok()
        if p == "/api/dhcp/scopes/removeReservedLease":
            sc = d["scopes"][q["name"]]
            sc["reservedLeases"] = [r for r in sc["reservedLeases"] if r["hardwareAddress"] != q["hardwareAddress"]]
            return ok()
        if p == "/api/dhcp/leases/list":
            return ok({"leases": d["leases"]})
        if p == "/api/dhcp/leases/remove":
            if not any(x["hardwareAddress"] == q["hardwareAddress"] and x["scope"] == q["name"] for x in d["leases"]):
                raise ValueError("No lease was found for hardware address: " + q["hardwareAddress"])
            d["leases"] = [x for x in d["leases"] if x["hardwareAddress"] != q["hardwareAddress"]]
            return ok()
        if p == "/api/_mock/lease":
            d["leases"].append({"scope": q["scope"], "type": "Dynamic", "hardwareAddress": q["hardwareAddress"], "clientIdentifier": "1-" + q["hardwareAddress"],
                                "address": q["address"], "hostName": q.get("hostName"), "leaseObtained": "2026-10-10T08:00:00Z", "leaseExpires": "2026-10-11T08:00:00Z"})
            return ok()
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
