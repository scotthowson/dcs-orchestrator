#!/usr/bin/env python3
"""Text-level edits of a compose file for the VPN (.lib/vpn.sh): the file is never parsed and written back, so every
line DCS does not touch stays byte for byte as it was, comments included, and an attach followed by a detach gives the
original file back exactly.

  attach  FILE SERVICE CONTAINER TAG [ENVFILE...]  -> {"content", "saved": [[offset, text]...], "ports": [lines], "targets": [ports]}
      takes the service's ports/networks/hostname/dns... out (they cannot live next to network_mode: container:) and puts
      one marker line, network_mode: "container:CONTAINER"  # DCS VPN: TAG, where the first of them was. ports are the
      service's port lines with ${VAR} filled from the ENVFILEs (they move into another stack, whose .env does not have them).
  detach  FILE SERVICE SAVED_JSON                 -> {"content"}   (the marker out, every saved block back at its offset)
  add-ports FILE SERVICE TAG PORTS_JSON           -> {"content"}   (the lines under SERVICE's ports:, each ending # moved by DCS for TAG)
  remove-ports FILE TAG                           -> {"content"}   (every line ending # moved by DCS for TAG)
  selftest

Exit 2 with {"error"} on a file it cannot edit safely. Standard library only.
"""
import json
import re
import sys

MOVED_KEYS = ("ports", "expose", "networks", "network_mode", "hostname", "dns", "dns_search", "dns_opt",
              "mac_address", "extra_hosts", "links")


class EditError(Exception):
    pass


def indent(line):
    return len(line) - len(line.lstrip(" "))


def blank(line):
    s = line.strip()
    return s == "" or s.startswith("#")


def service_span(lines, service):
    """(header index, end index exclusive, key indent) of SERVICE under the top-level services:."""
    top = None
    for i, l in enumerate(lines):
        if re.match(r"^services:\s*(#.*)?$", l.rstrip("\r\n")):
            top = i
            break
    if top is None:
        raise EditError("the file has no services: section")
    i = top + 1
    svc_ind = None
    while i < len(lines):
        l = lines[i]
        if not blank(l):
            if indent(l) == 0:
                break
            if svc_ind is None:
                svc_ind = indent(l)
            if indent(l) == svc_ind:
                m = re.match(r"^\s*([\"']?)([A-Za-z0-9_.-]+)\1:\s*(#.*)?$", l.rstrip("\r\n"))
                if m and m.group(2) == service:
                    end = i + 1
                    while end < len(lines) and (blank(lines[end]) or indent(lines[end]) > svc_ind):
                        end += 1
                    # trailing blank or comment lines belong to what follows
                    while end > i + 1 and blank(lines[end - 1]):
                        end -= 1
                    key_ind = None
                    for k in range(i + 1, end):
                        if not blank(lines[k]):
                            key_ind = indent(lines[k])
                            break
                    if key_ind is None:
                        raise EditError("the service %s is empty" % service)
                    return i, end, key_ind
        i += 1
    raise EditError("no service %s in the file" % service)


def key_blocks(lines, start, end, key_ind):
    """[(key, first, last exclusive)] of the service's keys."""
    out = []
    k = start + 1
    while k < end:
        l = lines[k]
        if not blank(l) and indent(l) == key_ind:
            m = re.match(r"^\s*([A-Za-z0-9_.-]+):", l)
            key = m.group(1) if m else ""
            j = k + 1
            while j < end and (blank(lines[j]) or indent(lines[j]) > key_ind):
                j += 1
            while j > k + 1 and lines[j - 1].strip() == "":
                j -= 1
            # comments at the key's own indent after the block belong to the next key
            while j > k + 1 and blank(lines[j - 1]) and indent(lines[j - 1]) <= key_ind:
                j -= 1
            out.append((key, k, j))
            k = j
        else:
            k += 1
    return out


def read_env(paths):
    env = {}
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                for l in f:
                    m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", l.rstrip("\r\n"))
                    if not m or m.group(1) in env:
                        continue
                    v = m.group(2).strip()
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                        v = v[1:-1]
                    env[m.group(1)] = v
        except OSError:
            pass
    return env


def interpolate(text, env):
    def rep(m):
        name = m.group(1) or m.group(4)
        val = env.get(name, "")
        op, dflt = m.group(2), m.group(3)
        if op == ":-" and val == "":
            return dflt
        if op == "-" and name not in env:
            return dflt
        return val
    text = text.replace("$$", "\0")
    text = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)", rep, text)
    return text.replace("\0", "$$")


def port_targets(port_lines):
    """The container side of each port: '8091:8080/tcp' -> 8080; long syntax target: 8080."""
    out = []
    for l in port_lines:
        s = l.split(" #", 1)[0].strip()
        m = re.match(r"^-?\s*target:\s*[\"']?(\d+)", s)
        if m:
            out.append(int(m.group(1)))
            continue
        if s.startswith("- "):
            p = s[2:].strip().strip("\"'").split("/")[0].split(":")[-1].split("-")[0]
            if p.isdigit():
                out.append(int(p))
    return sorted(set(out))


def attach(path, service, container, tag, envs):
    with open(path, encoding="utf-8", newline="") as f:
        lines = f.read().splitlines(keepends=True)
    start, end, key_ind = service_span(lines, service)
    if any("# DCS VPN:" in l for l in lines[start:end]):
        raise EditError("the service %s already goes through the VPN" % service)
    blocks = [b for b in key_blocks(lines, start, end, key_ind) if b[0] in MOVED_KEYS]
    ports = []
    for key, a, b in blocks:
        if key == "ports":
            first = lines[a]
            if re.search(r"ports:\s*\[", first):
                raise EditError("write the ports of %s as a list (one - \"host:container\" a line) first" % service)
            ports = [l.rstrip("\r\n") for l in lines[a + 1:b] if not blank(l)]
    env = read_env(envs)
    ports = [interpolate(l, env) for l in ports]
    if ports:
        base = min(indent(l) for l in ports)
        ports = [l[base:] for l in ports]
    nl = "\r\n" if lines[start].endswith("\r\n") else "\n"
    marker = "%snetwork_mode: \"container:%s\"  # DCS VPN: %s (Config: VPN; switch it off there, do not edit this line)%s" % (
        " " * key_ind, container, tag, nl)
    saved = []
    out = lines[:start]
    svc = lines[start:end]
    removed = set()
    for key, a, b in blocks:
        saved.append([a - start, "".join(lines[a:b])])
        removed.update(range(a - start, b - start))
    kept = [l for i, l in enumerate(svc) if i not in removed]
    pos = blocks[0][1] - start if blocks else len(kept)
    kept.insert(pos, marker)
    out += kept + lines[end:]
    return {"content": "".join(out), "saved": saved, "ports": ports, "targets": port_targets(ports)}


def detach(path, service, saved):
    with open(path, encoding="utf-8", newline="") as f:
        lines = f.read().splitlines(keepends=True)
    start, end, _ = service_span(lines, service)
    svc = lines[start:end]
    marks = [i for i, l in enumerate(svc) if "# DCS VPN:" in l]
    if not marks:
        raise EditError("the service %s does not go through the VPN" % service)
    for i in reversed(marks):
        del svc[i]
    for off, text in sorted(saved, key=lambda s: s[0]):
        block = text.splitlines(keepends=True)
        off = min(max(int(off), 1), len(svc))
        svc[off:off] = block
    return {"content": "".join(lines[:start] + svc + lines[end:])}


def add_ports(path, service, tag, ports):
    with open(path, encoding="utf-8", newline="") as f:
        lines = f.read().splitlines(keepends=True)
    start, end, key_ind = service_span(lines, service)
    nl = "\r\n" if lines[start].endswith("\r\n") else "\n"
    suffix = "  # moved by DCS for %s" % tag
    blocks = [b for b in key_blocks(lines, start, end, key_ind) if b[0] == "ports"]
    if blocks:
        _, a, b = blocks[0]
        if re.search(r"ports:\s*\[", lines[a]):
            raise EditError("the VPN's ports are written as [...]: write them as a list first")
        items = [l for l in lines[a + 1:b] if not blank(l)]
        item_ind = indent(items[0]) if items else key_ind + 2
        new = [" " * item_ind + p + suffix + nl for p in ports]
        lines[b:b] = new
    else:
        new = [" " * key_ind + "ports:" + suffix + nl] + [" " * (key_ind + 2) + p + suffix + nl for p in ports]
        lines[end:end] = new
    return {"content": "".join(lines)}


def remove_ports(path, tag):
    with open(path, encoding="utf-8", newline="") as f:
        lines = f.read().splitlines(keepends=True)
    suffix = "  # moved by DCS for %s" % tag
    return {"content": "".join(l for l in lines if not l.rstrip("\r\n").endswith(suffix))}


def selftest():
    import os
    import tempfile
    app = ('services:\n  qbittorrent:\n    container_name: qBittorrent\n    image: lscr.io/linuxserver/qbittorrent:latest\n'
           '    hostname: qb\n    environment:\n      - WEBUI_PORT=8080\n    # the web page\n    ports:\n'
           '      - "${PORT_QBITTORRENT:-8091}:8080"\n      - "6881:6881/udp"\n    networks:\n      - proxy\n'
           '    restart: unless-stopped\n  other:\n    image: alpine\n    ports:\n      - 1:1\nnetworks:\n  proxy:\n    external: true\n')
    vpn = ('services:\n  gluetun:\n    container_name: Gluetun\n    image: qmcgaw/gluetun\n    ports:\n'
           '      - "127.0.0.1:8899:8000"\n    restart: unless-stopped\n')
    d = tempfile.mkdtemp()
    a, v, e = (os.path.join(d, n) for n in ("app.yml", "vpn.yml", ".env"))
    open(a, "w").write(app)
    open(v, "w").write(vpn)
    open(e, "w").write("PORT_QBITTORRENT=9091\n")
    r = attach(a, "qbittorrent", "Gluetun", "media/qbittorrent", [e])
    assert r["ports"] == ['- "9091:8080"', '- "6881:6881/udp"'], r["ports"]
    assert r["targets"] == [6881, 8080], r["targets"]
    assert "hostname" not in r["content"].split("other:")[0] and "proxy\n    restart" not in r["content"]
    assert r["content"].count("network_mode: \"container:Gluetun\"") == 1
    assert "    # the web page\n" in r["content"]
    assert "ports:\n      - 1:1" in r["content"]
    open(a, "w").write(r["content"])
    try:
        attach(a, "qbittorrent", "Gluetun", "x", [])
        raise AssertionError("a second attach must refuse")
    except EditError:
        pass
    back = detach(a, "qbittorrent", json.loads(json.dumps(r["saved"])))["content"]
    assert back == app, back
    p = add_ports(v, "gluetun", "media/qbittorrent", r["ports"])["content"]
    assert '      - "9091:8080"  # moved by DCS for media/qbittorrent\n' in p and p.index("8899") < p.index("9091")
    open(v, "w").write(p)
    assert remove_ports(v, "media/qbittorrent")["content"] == vpn
    open(v, "w").write("services:\n  gluetun:\n    image: x\n")
    p = add_ports(v, "gluetun", "s/a", ['- "1:2"'])["content"]
    open(v, "w").write(p)
    assert remove_ports(v, "s/a")["content"] == "services:\n  gluetun:\n    image: x\n"
    assert port_targets(["- target: 80", "  published: 81", '- "127.0.0.1:5000:5001/tcp"', "- 7000-7001:7000-7001"]) == [80, 5001, 7000]
    print("vpn-compose selftest: ok")


def main(argv):
    try:
        op = argv[1] if len(argv) > 1 else ""
        if op == "attach" and len(argv) >= 6:
            r = attach(argv[2], argv[3], argv[4], argv[5], argv[6:])
        elif op == "detach" and len(argv) == 5:
            r = detach(argv[2], argv[3], json.loads(argv[4]))
        elif op == "add-ports" and len(argv) == 6:
            r = add_ports(argv[2], argv[3], argv[4], json.loads(argv[5]))
        elif op == "remove-ports" and len(argv) == 4:
            r = remove_ports(argv[2], argv[3])
        elif op == "selftest":
            selftest()
            return 0
        else:
            print(json.dumps({"error": "usage: attach|detach|add-ports|remove-ports|selftest"}))
            return 2
    except (EditError, OSError, ValueError) as e:
        print(json.dumps({"error": str(e)}))
        return 2
    print(json.dumps(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
