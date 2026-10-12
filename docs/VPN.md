# VPN: chosen containers through a WireGuard tunnel

DCS puts the containers you choose (qBittorrent, say) behind a WireGuard tunnel to Private Internet Access, with a
kill switch and PIA's forwarded port handed to qBittorrent. Nothing else on the server goes through it, so everything
else keeps its normal connection and speed.

**Turn it on first:** Config → Integrations → *VPN* (`VPN_ENABLED=true`). Until then the page (Security → VPN) is
hidden and every `/vpn/*` route, and `PUT /containers/{name}/vpn`, answers `404 feature_off`.

## How it is built

- **The tunnel** is Gluetun, the `gluetun` service (container `Gluetun`) of the `networking-security` stack, from the
  `vpn-gluetun` template. It uses Gluetun's *custom* WireGuard provider. Gluetun has no native PIA WireGuard support
  (see [its wiki](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/private-internet-access.md)), so
  DCS registers the WireGuard key itself, the way PIA's
  [manual-connections](https://github.com/pia-foss/manual-connections) scripts do.
  The template sits in `networking-security` because that stack already exists on every server and starts before
  `media-services`, so the tunnel is up before qBittorrent at boot.
- **Connect** (`POST /vpn/connect {username, password, region}`) does the following:
  1. It gets a token from the account (`/api/client/v2/token`).
  2. It reads PIA's server list and keeps the regions that forward a port. With `region: "auto"`, the default, it
     picks the region with the lowest connect time to its meta server. When none answers, it picks a Canadian one.
  3. It makes a fresh X25519 key (openssl) and registers it with the region's WireGuard server (`addKey` on :1337,
     checked against PIA's CA in `.lib/vpn-pia-ca.crt`).
  4. It writes the peer to the stack's `.env` (`VPN_WG_ENDPOINT_IP/PORT`, `VPN_WG_PUBLIC_KEY`, `VPN_WG_ADDRESSES`,
     `VPN_SERVER_NAME`, `VPN_REGION`, `VPN_REGION_ID`) and recreates Gluetun.

  The account is stored only after PIA accepts it. `GET /vpn/regions` lists the regions that forward a port,
  Canada's first.
- **Secrets.** The PIA account (`VPN_USER`, `VPN_PASS`), the WireGuard key (`VPN_WG_PRIVATE_KEY`) and the key of
  Gluetun's control server (`VPN_CONTROL_KEY`, which DCS makes itself) live in DCS's secret store. Before every start
  Gluetun gets them as files in `App-Data/Gluetun-VPN/secrets` (folder 700, files 600, mounted at `/run/secrets`).
  Gluetun reads them there, so they never appear in the compose file, the `.env`, `docker inspect`, a log or an
  answer. The compose file references only the auto-generated `VPN_CONTROL_KEY`, so the stack's secrets gate never
  blocks Traefik and the rest of `networking-security`.
- **Port forwarding** is Gluetun's (`VPN_PORT_FORWARDING=on`, provider `private internet access`, `SERVER_NAMES` =
  the server's name). PIA keeps the port for 60 days while `/gluetun` is kept.

## A container through the VPN

`PUT /containers/{name}/vpn {"on": true}`, or the switch on the VPN page:

- **Its service.** The service's `ports`, `expose`, `networks`, `network_mode`, `hostname`, `dns*`, `mac_address`,
  `extra_hosts` and `links` cannot live next to a shared network, so DCS takes them out. In their place it writes one
  line: `network_mode: "container:Gluetun"  # DCS VPN: <stack>/<service> …`. Nothing else in the file changes. DCS
  edits the text, not a parsed copy (`.lib/vpn-compose.py`), so comments and layout stay. What was taken out is
  kept in `.data/vpn/<stack>--<service>.json`, which also goes into the recovery bundle.
- **Its ports** move onto Gluetun's `ports:`, each line ending `# moved by DCS for <stack>/<service>`. A
  `${PORT_X:-8091}` is filled in from the container's own stack `.env`, because Gluetun's `.env` does not have it.
  Its web page answers on the same host port as before.
- **Its Traefik route** (`custom_routes/<stack>/<service>.yml`) points at `Gluetun` on the same port. Gluetun joins
  the `proxy` network.
- **Checks and restarts.** Both files go through the compose policy. If the policy refuses either one, both files
  are put back exactly as they were. Only the touched services are recreated, in this order: the container lets go
  of its ports, Gluetun takes them, then the container joins Gluetun. Two containers behind the VPN cannot listen on
  the same port (the second one is refused with 409), and port 8000 is Gluetun's own.
- **Off** (`{"on": false}`) puts everything back. Gluetun's ports go first, then the saved blocks return at their
  places. An attach followed by a detach gives both files back byte for byte.

**The kill switch** is Gluetun's firewall. A container behind it reaches the internet only through the tunnel. When
the tunnel is down, or Gluetun is paused or stopped, it reaches nothing.

## The minute clock

When the VPN is on, DCS checks the following every minute:

- **Gluetun restarted.** The containers behind it lost their network. If Gluetun is the same container, DCS restarts
  them. If Gluetun is a new container (an update or a recreate), DCS recreates them, because they still hold the old
  container's network.
- **The tunnel down for 2 minutes** raises `vpn_down`, which names the containers the kill switch has cut off. It is
  cleared when the tunnel is back. While the VPN is paused, nothing is raised. After 10 minutes down with a PIA
  account, DCS registers a new key (at most every 30 minutes), because PIA forgets keys it has not seen for a while.
- **PIA's forwarded port** goes into qBittorrent (any container whose image matches `qbittorrent`) through
  `/api/v2/app/setPreferences` (`listen_port`, `random_port: false`, `upnp: false`). DCS reaches it on Gluetun's
  published web port. If qBittorrent asks for a login, DCS uses the secrets `QBITTORRENT_USER` and
  `QBITTORRENT_PASS`. Without them, the status says what is missing.
- **A leak check** runs every 15 minutes, and on demand with `POST /vpn/leak-test`. Each container fetches its
  address from `VPN_IP_ECHO_URL` (`https://ipinfo.io/ip` by default). The result is one of these:
  - `tunnel`: the tunnel's address.
  - `leak`: the home address. This raises `vpn_leak`.
  - `offline`: no internet, which is the kill switch working.
  - `unknown`: neither address.

Both events are rules on the Notifications page, made once and on by default.

**Pause and resume** (`POST /vpn/pause`, `POST /vpn/resume`) stop and start Gluetun. The containers behind it have
no network while it is paused.

## Route the WireGuard clients through the VPN

`PUT /vpn/wireguard-clients {"on": true, "container": "WireGuard"}` sends the traffic of the WireGuard server's
clients (wg-easy) out through the tunnel. The server itself keeps the home address, so the phones still connect to
it from outside. What DCS does:

- The WireGuard container also joins Gluetun's network (`docker network connect`). DCS edits no compose file here, and
  the minute clock joins it again after a recreate.
- Its own default route stays the one it had before. Docker moves it to the network that sorts first by name, again
  at every restart, and DCS puts it back. The inbound UDP answers to the clients use that route.
- Inside the WireGuard container:
  - `ip rule add iif wg0 lookup 51821 pref 5211`, with `default via <Gluetun's address>` in table 51821.
  - Private destinations (10/8, 172.16/12, 192.168/16) stay on the main table, so the clients still reach the LAN.
  - A MASQUERADE of the clients' subnet onto Gluetun's network. The subnet is read from `WG_DEFAULT_ADDRESS`
    (wg-easy), `INTERNAL_SUBNET` (linuxserver) or `wg0`'s address.
- In Gluetun, FORWARD rules and a MASQUERADE onto `tun0` for that one address. These are applied at once with
  `docker exec`, and kept in `App-Data/Gluetun-VPN/iptables/post-rules.txt`, which Gluetun applies when it starts.
  Gluetun already routes its own Docker subnet locally, so `FIREWALL_OUTBOUND_SUBNETS` does not change.
- The kill switch applies to the clients too: with the tunnel down, their internet stops. Their LAN access does not.
- Off removes the rules, the route and the extra network.

The WireGuard container needs `ip` and `iptables`; wg-easy has both, and NET_ADMIN.

**Speed:** traffic from the clients now goes phone → home (your upload) → PIA → internet, and back the same way. Every
byte crosses your home connection twice, so the clients' speed is limited by your home upload and PIA's server. The rest
of the house is not affected.

## Setting it up (the owner)

1. Config → Integrations → VPN: on.
2. Security → VPN → *Set up*. This deploys the `vpn-gluetun` template into `networking-security` without starting
   it. *Your network* defaults to `192.168.0.0/16`.
3. Enter the PIA user name (`p1234567`) and its password. Leave the region on *Fastest that forwards a port*, or
   pick one. Press Connect.
4. Switch qBittorrent on in the list. If qBittorrent asks for a login on its web API, store the secrets
   `QBITTORRENT_USER` and `QBITTORRENT_PASS`. You can instead tick *Bypass authentication for clients on localhost*
   in qBittorrent.
5. Optional: *Route my WireGuard clients through the VPN*.

## Routes

| Method | Path | Who |
|---|---|---|
| GET | `/vpn/status`, `/vpn/regions` | every account |
| POST | `/vpn/connect`, `/vpn/pause`, `/vpn/resume`, `/vpn/leak-test` | admin |
| PUT | `/containers/{name}/vpn`, `/vpn/wireguard-clients` | admin |

## Tests

- `tests/smoke.sh`, section *VPN*: a stand-in Gluetun control server, qBittorrent and PIA (`tests/mock-gluetun.py`) and
  a stand-in `docker`. It covers the switch, connect, attach and detach (byte for byte), the route, the policy, the
  port into qBittorrent, restarts, the alerts, leaks, pause, the roles and the secrets.
- The real proof was run in a Docker-in-Docker sandbox with a WireGuard server and Gluetun's custom provider. It is
  described under *Unreleased* in `CHANGELOG.md`.
