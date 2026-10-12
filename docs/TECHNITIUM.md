<sub>[← Documentation](README.md)</sub>

# Technitium DNS: the home's resolver, run from DCS

[Technitium DNS Server](https://technitium.com/dns/) answers every name the house asks for: it blocks ads,
trackers and what the children should not reach, forwards the rest encrypted, and keeps a log of who asked
what. DCS runs it from **Security → Technitium** (also linked from DNS & routes), so Technitium's own console is
needed once: to make an API token.

**Turn it on first:** Config → Integrations → *Technitium DNS* (`TECHNITIUM_ENABLED=true`). Until then the page, its
card on DNS & routes and every `/dns/technitium/*` route are off (404 `feature_off`), and the minute clock does nothing
for it. A server that had Technitium connected before this switch existed is switched on by itself once. Turning it off
leaves Technitium as it is: a bedtime or a device block in force stays until the switch is back on.

## The plan for the house

| Part | Where | Does |
|---|---|---|
| Primary | an LXC container on Proxmox, `192.168.2.53`, console on `:5380` | the resolver every device uses first; DHCP for the house |
| Secondary | a Raspberry Pi, `192.168.2.207`, console on `:5380` | the same answers when the primary is down or rebooting |
| DCS | the hub | the page, the kids' groups and their bedtime clock, and keeping the secondary equal to the primary |

1. **Install** Technitium on both (its install script on the LXC and the Pi, or the `technitium-dns` template on a
   DCS host: set its DNS port to 53 once nothing else on the host uses it).
2. **Make an API token** on each: sign in to `http://<ip>:5380`, your name at the top right → **Create API Token**.
   The token has the rights of the account that made it; an admin's is what DCS needs.
3. **Connect** both on the Technitium page (address + token, *primary* and *secondary*). The address is kept in
   `.env` (`TECHNITIUM_URL`, `TECHNITIUM_SECONDARY_URL`), the token in the secrets store (`TECHNITIUM_TOKEN`,
   `TECHNITIUM_SECONDARY_TOKEN`), never in a log or an answer.
4. **Apply baseline** (it lists what it sets and asks first). It changes only what differs; a second run changes
   nothing:
   - forwarders Quad9 (`dns.quad9.net`: 9.9.9.9, 149.112.112.112) and Mullvad (`dns.mullvad.net`: 194.242.2.2) over
     TLS, one query at a time, DNSSEC validation on, no IPv6 preference;
   - blocklists Hagezi Pro, Threat Intelligence Feeds and DoH bypass (the `wildcard/*-onlydomains.txt` files: one
     domain a line, which Technitium reads as the domain and its subdomains), updated daily; lists you added stay;
   - the query log: the **Query Logs (Sqlite)** app, 30 days;
   - the **Advanced Blocking** app (the kids' groups);
   - the names `dns1` / `dns2`, a cache of 20 000 entries, serve-stale on.
5. **Move DHCP** from the ISP router to Technitium with the page's guided flow (**DHCP** tab, below). Devices pick it
   up as their leases renew (or after a reconnect); with Technitium serving DHCP, every device tells its name.

## The page

- **Overview**: both servers (reachable, version, blocking, in sync), queries and blocked over the last hour, day
  or week, the top clients, domains and blocked names (**Allow** on a blocked one), **Pause blocking** for 5, 15
  or 60 minutes on both (it comes back by itself; **Resume** ends it early), **Sync now**.
- **Kids**: one card per group (a child, or all the boys) with what is in force at a glance (*Bedtime*, *Games blocked
  until 18:00*, *Allow-list*, *SafeSearch*), today's lookups, blocked and top name, and **Pause 30 min**. Its editor has
  the devices, SafeSearch and YouTube, the categories, the time windows, the allow-list mode and the exceptions (below).
- **Activity**: one device's recent queries from both servers, the blocked ones marked, with Allow / Block.
- **Devices**: the device directory (below): a name and an icon for each, its group, its address pinned, a block
  until a time, its latest queries.
- **DHCP**: Technitium's scope and leases, and the guided move from the router.
- **Lists**: each blocklist's health on both servers (its names, its last update, why a download failed) with
  **Update lists now**, the blocklists, and the names allowed or blocked for everyone.
- **Servers** (admin): each server's address and token, its version (and the command that updates it when Technitium
  has a newer one), and the backups (**Back up now**, **Restore**).
- On the **Dashboard**, a Technitium tile (today's queries and blocked, both servers, in sync; add it from the card
  picker on a dashboard saved before it existed), and its alerts in **Needs your attention**.

A viewer sees the page read-only (the devices and DHCP included) and does not see a device's queries.

## The device directory

Every device of the house, named once: `.data/technitium/devices.json`, one record per MAC address (or per IP address
while no MAC is known). **Scan the network** (and the API's clock every 5 minutes) gathers:

| Source | Gives | Needs |
|---|---|---|
| Technitium's DHCP leases and reservations | the name each device gives itself, its MAC, whether its address is reserved | Technitium serving DHCP |
| The hub's neighbour table | every device on the LAN with its MAC, even while the router does DHCP | the hub on the LAN; one ping to each address of its /24 first (a private network only, 0.2 s each, at most every 5 minutes) |
| mDNS | names like `Toms-iPad.local` | `avahi-resolve-address` on the hub (avahi-tools) |
| Reverse DNS on the primary | the names Technitium (or the router) knows | — |
| The query log | who asked in the last 24 hours, and how much of it was blocked | the Query Logs (Sqlite) app |

The vendor comes from the MAC's first half: `.config/oui-common.txt` holds the prefixes of the vendors a home network is
full of (Apple, Samsung, Google, Amazon, Sony, Microsoft, Nintendo, Raspberry Pi, Espressif, TP-Link, Ubiquiti, …),
and **Update the vendor list** fetches IEEE's whole list once (`.data/technitium/oui.txt`). A phone or tablet that uses a
private (random) MAC shows *Private address*: Android and iOS do that per network, so the address stays the same on
this Wi-Fi.

The icon is guessed until you pick one, again on every scan: from the name the device gives itself (then its nickname)
first, then its vendor. `ScottsTV` is a TV, `OnePlus-Pad` a tablet, `OnePlus-15` a phone, `Howson-Ubuntu` a desktop,
`pi-hole` a server; with no telling name a Samsung, Apple or Google device is a phone, a Nintendo a console, a Sagemcom
or Ubiquiti a router, an Espressif board an iot device. The page draws a guess with a dotted ring; one you picked is never
guessed over. A nickname shows everywhere the page names a device: the top
clients, a device's queries, the groups. A group holds its devices by their directory id, so a device that gets
another address stays in its group. **Forget** drops a device; seen again, it comes back with its nickname and icon
until the forgotten ones are cleared. **Block until …** blocks every name for one device (bedtime's rule) until a time;
the clock lifts it. **Pin address** reserves its current address in Technitium's DHCP (only once Technitium has a scope:
while the router still does DHCP there is nothing to reserve in).

IPv4 only: an IPv6 client of the query log is not a device here (IPv6 is off on the house's router).

## Moving DHCP from the router (the DHCP tab)

1. **Scan the network**, so the directory has every device.
2. **Create the scope here, off.** Made from the hub's network: `.100`-`.199`, the router as gateway, DNS = the primary
   then the secondary, domain `home`, leases of 24 h, ping check on (an address that answers is not offered). With
   *Keep every known device on its current address* (on), every device of the directory with a MAC gets a reservation
   at the address it has now, named or not, seen in a lease or only in the neighbour table, so nothing changes address
   at the flip. Machines with an address set by hand never ask and are not affected. Technitium turns a new scope on
   when it makes one, so DCS turns its stock *Default* scope (off) into this one instead, or turns the new one off at once.
3. **Turn the router's DHCP off.** Bell Home Hub 4000: Advanced tools and settings → DHCP.
4. **Turn DHCP on here.** Both resolvers must stay up from now on: every device is told to use them.
5. **Renew a device** (turn its Wi-Fi off and on) and check it: its lease shows the DNS servers it was given, green
   when they are Technitium's.

Technitium's DHCP scopes are on the primary only; the secondary is not given a copy (two DHCP servers would hand out the
same addresses). If the primary is down for long, turn the router's DHCP back on.

## How the groups work

DCS keeps the groups in `.data/technitium/groups.json` and writes them into the Advanced Blocking app's config on
both servers (DCS owns that config: what was set for the app in Technitium's console is replaced). A device is an
address (or a small network such as `192.168.2.48/29`); a device is in one group at a time; a device in no group
(yours) gets the house's blocking alone: no SafeSearch, no YouTube restriction, no window.

A group has:

| Part | Does |
|---|---|
| **SafeSearch** (`safe_search`, on or off) | Google (`www.google.com`, `www.google.ca`), Bing (`www.bing.com`) and DuckDuckGo (`duckduckgo.com`, `www.duckduckgo.com`, `start.duckduckgo.com`) answer the address of their safe name (`forcesafesearch.google.com`, `strict.bing.com`, `safe.duckduckgo.com`) for the group's devices only. Exact names: `mail.google.com` or `links.duckduckgo.com` resolve as usual. |
| **YouTube** (`youtube`: off, moderate, strict; strict for a new group) | `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com` and `www.youtube-nocookie.com` answer `restrict.youtube.com` (strict) or `restrictmoderate.youtube.com` (moderate). |
| **Categories** (`categories`, always on) | Blocked all day. Each is maintained lists and/or a short built-in set of names (`.config/kids-categories.json`, its sources cited there): see the table below. |
| **Time windows** (`windows`) | From a time to a time on chosen days (a window from 20:30 to 07:00 runs into the next morning), each with a switch: *every name* (`scope: all`, bedtime's rule: everything blocked but this server's own domains) or *some categories* (`scope: categories`, e.g. games and video 16:00–18:00 on school days). Bedtime is the first window, named *Bedtime*. Two presets are a click away, both off until switched on: *Homework: games and video blocked 16:00–18:00 Mon–Fri* and *No internet 16:00–18:00 Mon–Fri*. |
| **Allow-list mode** (`mode: allowlist`) | For the youngest: every name is blocked but the group's sites (`sites`, a switch each), the tablet's essentials and its exceptions. The preset *Little ones* offers YouTube Kids, PBS Kids, Khan Academy Kids, Netflix, Disney+ and Roblox. |
| **Exceptions** (`allowed`) and **extras** (`blocked`) | Up to 100 names each, with their subdomains. An exception wins over every block of the group (a category, a window that blocks categories), but not over a window that blocks everything; one that would undo the group's SafeSearch or YouTube (`youtube.com` with YouTube on) is refused. |

**How SafeSearch works per group.** Advanced Blocking answers a blocked name either NXDOMAIN or with addresses, and a
block list can carry addresses of its own (`blockListUrls`/`regexBlockListUrls` entries `{url, blockAsNxDomain: false,
blockingAddresses}`; a group's own `blocked` names only get the group's). So a group with SafeSearch gets one regex list
per search engine (the exact names, `^www\.google\.com$`) with its safe name's addresses, and the group's other blocks
stay NXDOMAIN. Technitium downloads those lists from this API (`GET /dns/technitium/kids-lists/{google,bing,duckduckgo,youtube}.txt`,
public: nothing secret in them) at the address other machines reach it by: `FLEET_SELF_URL`, else
`http://<this server's LAN address>:<API_PORT>`. Technitium must be able to reach it (an `API_IP_WHITELIST` must let the
two Technitiums in); it keeps its downloaded copy if it cannot. The addresses are resolved by the primary when a group
first needs them and again once a day (kept in `state.json`; a name that does not resolve keeps its last addresses, else
the ones in `.config/kids-categories.json`). A window that blocks everything comes first: at bedtime the search engines
are blocked too. Proven on `technitium/dns-server` 15.6.1 with Advanced Blocking 11.2.1: two clients asking the same
server, the kid's `www.google.com` answered `216.239.38.120`, the owner's Google's own addresses.

| Category | Blocks | Source |
|---|---|---|
| Adult content | pornography and other adult sites | Hagezi NSFW |
| Gambling | betting, casinos, lotteries | Hagezi Gambling |
| Social media | Facebook, Instagram, TikTok, X, Snapchat, Reddit, Discord, Threads (Facebook's list also holds WhatsApp) | The Block List Project (Facebook, TikTok, Twitter) + built-in names |
| Video and streaming | Netflix, Twitch, TikTok, Disney+, Crave, Prime Video (YouTube has its own setting) | built-in names |
| Games | Roblox, Fortnite/Epic, Minecraft, Steam, EA | built-in names |
| Chat | WhatsApp, Discord, Messenger, Telegram | The Block List Project (WhatsApp) + built-in names |
| Shopping | Amazon (.com, .ca), eBay, Temu, AliExpress, Shein | built-in names |
| Search engines without SafeSearch | the ones that cannot be made safe | Hagezi No SafeSearch |
| VPNs, proxies and other DNS | the ways around the filter | Hagezi DoH/VPN/TOR/Proxy bypass |
| Piracy | torrent sites, pirate streaming, warez | Hagezi Anti Piracy |

**Consoles stay out of a kids' group with games blocked.** The games category leaves `xboxlive.com` and `playstation.com`
alone, but an Xbox or a PlayStation also needs Microsoft's and Sony's other services: put the consoles in a group of their
own (bedtime, adult and gambling) rather than blocking games for them. A Fire tablet needs Amazon: shopping is not for it.

**Allow-list mode: what the tablet still reaches.** With everything else blocked an Android tablet needs: the
connectivity check (`connectivitycheck.gstatic.com`, `connectivitycheck.android.com`, `clients1/3/4.google.com`,
`www.gstatic.com`; without it Android says there is no internet), the clock (`time.android.com`, `android.pool.ntp.org`),
Google sign-in (`accounts.google.com`, `www.googleapis.com`, `android.googleapis.com`), Google Play and its downloads
(`play.google.com`, `play.googleapis.com`, `play-fe.googleapis.com`, `play-lh.googleusercontent.com`,
`android.clients.google.com`, `gvt1.com`, `gvt2.com`, `gvt3.com`) and push messages (`mtalk.google.com`,
`fcm.googleapis.com`, `firebaseinstallations.googleapis.com`). Exact names (the `gvt` and `ntp` ones with their
subdomains), nothing broader: `googleapis.com` as a whole would let YouTube's API through. YouTube Kids is
`youtubekids.com`, `googlevideo.com` (the videos), `ytimg.com` and `ggpht.com` (pictures); its API
(`youtubei.googleapis.com`, shared with the full YouTube app) answers in restricted mode when the group's YouTube setting
is on, so the full YouTube app may half work in restricted mode on that tablet: remove it there. These names come from
the services' documentation and common lists, not from watching each app: if one misbehaves, its blocked names are in the
device's activity, and an exception lets one through.

**The clock.** The API's minute clock (the automation loop: `AUTOMATIONS_ENABLED` must stay `true`) renders the config
every minute and writes it only when it differs from the last one written (a window starting or ending, a pause running
out, a device's block ending): a minute with no change writes nothing. Each window that starts or ends is a line in the
audit log (`TECHNITIUM_BEDTIME` for bedtime, `TECHNITIUM_WINDOW` for the others). Its state is
`.data/technitium/state.json`, so a restart of the API changes nothing. **Pause 30 min** lifts a group's windows (all of
them, or one) for 30 minutes. Technitium answers a blocked name with a TTL of 30 seconds, so a change is in force within
half a minute.

**The report** (`GET /dns/technitium/groups/{id}/report?range=lastDay|lastWeek`, the admin's): the group's devices'
lookups from the query log of both servers (the newest 5000 per device and server), the blocked, the top names and the
top blocked (per device too), and the blocked per category: a category's built-in names, and its lists, of which DCS keeps a
copy (`.data/technitium/lists`, fetched again when a day old); the rest is *other*.

### Moving to these controls (version 2 of groups.json)

The first time this version reads `groups.json`:

- If the house's SafeSearch or YouTube switch was on, every group gets that setting and the house switch goes off: no child
  loosens, and your own devices (in no group) are not filtered any more. The minute clock writes the groups first, then
  removes the house's forced zones. With no group yet, the house switch stays as it was.
- The consoles of a group (a device whose icon is *console*, or whose icon is still a guess and whose vendor is Nintendo,
  Sony or Microsoft) move to a new group *Consoles*: the first group's bedtime, adult content and gambling blocked, no
  games block, no other window.
- A group's lists become its categories and its bedtime its first window.

What it did is in `groups.json` (`migration.notes`) and on the Kids tab.

## SafeSearch and YouTube for the whole house (optional)

Off by default: a group's own setting is the way. The switch forces every device of the house, yours too: each forced
name (`www.google.com`, `www.bing.com`, `duckduckgo.com`, `www.duckduckgo.com`; for YouTube `www.youtube.com`,
`m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com`) gets a *Forwarder* zone
of its own whose apex is an ANAME to the safe name; every other name under it resolves as usual. Turning it off removes
those zones (a zone of the same name you made yourself, of another type, is left alone).

## Local names: your routes inside the house, devices by name

**Resolve my routes locally** (DNS & routes, and the Technitium page; `POST /dns/technitium/local {routes: true}`, off
by default). Your public services go Cloudflare → Traefik on the hub, so from inside the house every request leaves
for the internet and comes back. With the switch on, each route host under a domain this server serves
(`jellyfin.howson.dev`, and the hosts of every extra domain) answers the hub's LAN address (its default route's) on
both Technitiums, with a TTL of 60. A VM's route answers the hub's address too: the hub's Traefik fronts it.

- **One zone per route host, never one for the domain.** A Primary zone is authoritative: a `howson.dev` zone would
  answer NXDOMAIN for every name DCS does not route. So `jellyfin.howson.dev` is a zone of its own whose apex is an A
  record (comment `dcs-local`), and `anything-else.howson.dev` still goes to the forwarders. The domain's own apex is
  never made local. A name under a routed host (`x.jellyfin.howson.dev`) answers NXDOMAIN inside the house.
- **Kept in step**: a route renamed, deleted or deployed, a domain added or removed, a VM's routes changing: at once;
  anything else within a minute (the minute clock compares and writes nothing when nothing changed).
- **Switching off removes exactly the zones DCS made** (tracked per server in `.data/technitium/local-zones.json`). A
  zone of that name you made yourself is left alone (and said in the answer).
- Sign-in (Authelia) and the certificates work as before: the name is the same and Traefik serves the same
  certificate. What LAN clients skip is Cloudflare (its WAF, its bans): that is the point.

**Devices by name.** The DHCP scope DCS makes registers every lease as `<hostname>.home` (Technitium's dynamic DNS,
`dnsUpdates`; Technitium makes the `home` zone with the first lease; a scope that hands out addresses without it is
turned on by the minute clock). A device's nickname is a name too: *Tom's tablet* answers `tom-s-tablet.home` (an A
record DCS owns, comment `dcs-name`; DCS makes the `home` zone when DHCP has not). It follows a new nickname, goes when
the device is forgotten, and the device drawer's *Also answer* switch (`home_answer`, on by default) turns it off for
one device. A static machine gets its name the same way. No reverse (PTR) records: a reverse zone here would hide the
router's own reverse names, which the device scan reads.

**The secondary gets the zone by transfer.** It does no DHCP, so the lease names exist only on the primary. DCS makes
`home` a *Secondary* zone on the secondary, transferred from the primary, and lets the primary transfer it to the
secondary's address and NOTIFY it on every change. That is simpler than copying records: the lease names follow with
no work from DCS (copying would need a diff every minute). It needs both Technitiums connected by their IPv4 address.

## Keeping the secondary in step

After every change DCS makes, and on **Sync now**, the secondary gets the primary's forwarders and their
settings, blocklists, cache size, the allowed and blocked names, the apps (installed when missing) with their
configs, the forced SafeSearch zones and the local names above. The status compares a fingerprint of all of that on both
(`in_sync`). DHCP scopes and anything else made in Technitium's console are not copied.

## The safety net: alerts, Needs your attention, backups

DCS watches both servers from the minute clock (the API's automation loop, in the background: a server that does not
answer never holds the clock up) and says each problem **once**, when it starts, and once more when it is over. Each
goes to the activity log, to the Integrations webhooks that subscribe to it, and through a notification rule to Discord
or ntfy. The rules are made the first time the clock runs, so they are on the **Notifications** page like every other
event: switch one off, change its priority or its cooldown there (a rule you delete is not made again).

| Event | When | Rule | Fix (Needs your attention) |
|---|---|---|---|
| `technitium_down` | a server did not answer two minute checks in a row; over when it answers | on | open the page (Servers) |
| `technitium_out_of_sync` | the two fingerprints have differed for 10 minutes and the sync DCS then tried failed (it tries every 10 minutes); over when they agree | on | **Sync now** |
| `technitium_lists_stale` | a server's blocklists were last updated more than 48 hours ago, or the last download of one of them failed (which list, and Technitium's reason) | on | **Update lists now** |
| `technitium_dhcp_pool` | the primary's DHCP scopes that are on have given out more than 80 % of their addresses | on | open the DHCP tab |
| `technitium_new_device` | a device with a MAC address is seen for the first time: *New device on the network: Samsung (a4:c3:f0:12:34:56), 192.168.2.142, named galaxy-s24 by DHCP*, with a link to the Devices tab (`DASHBOARD_PUBLIC_URL`). More than 5 at once are one message. The first look learns what is already there and says nothing | on | — |
| `technitium_bedtime` | a kids' group went into or out of bedtime | off | — |
| `technitium_device_blocked_expired` | a device's *Block until* ran out (a block lifted by hand is not) | off | — |

`GET /dns/technitium/status` carries the alerts in force (`alerts`: event, server, headline, message, the fix as
`action`, since when): the dashboard's **Needs your attention** lists them. Its state is `.data/technitium/alerts.json`.

Per server the status also has: `update_available` and `update_version` (Technitium's own update check, asked every 6
hours; the Servers sheet then shows the command that updates it, run on that machine:
`curl -sSL https://download.technitium.com/dns/install.sh | sudo bash`), `lists` (each blocklist's `entries`,
`last_updated` and `error`, and the `total` of names blocked: Technitium says per list only in its log, so the last
three days of it are read, at most every 2 minutes; when its log says nothing of them, only the total is known and
`note` says so) and, on the primary, `dhcp` (`enabled`, `leases`, `pool_size`, `pct`). **Update lists now**
(`POST /dns/technitium/lists/update`) makes both download their lists again.

### Backups

Every night at `TECHNITIUM_BACKUP_HOUR` (3 by default, local time; `off` = never), and on **Back up now**
(`POST /dns/technitium/backup`), DCS takes each server's own backup (Technitium's `GET /api/settings/backup`) into
`.data/technitium/backups/<server>-<date>_<time>.zip` and keeps the newest 14 of each. The zip holds the settings, the
zones, the allowed and blocked names, the DHCP scopes and the log settings. It leaves out what is big or comes back by
itself: the query logs and stats, the downloaded lists and the apps (with the query log's database). It also leaves
out Technitium's accounts and API tokens, which have no place in a file that goes into DCS's own backups. Next to each
zip a `.json` keeps what a restore puts back on top: the blocklist addresses and the apps with their configs. A failed
nightly backup is tried twice more, 30 minutes apart, and said (`backup_failed`). `.data` is in every DCS backup and
recovery bundle, so the device directory, the groups, the state and these zips go with them.

**Restore** (`POST /dns/technitium/restore {server, file, confirm: true}`, the Servers sheet) hands the zip to
Technitium (`POST /api/settings/restore`): its settings, zones and names become the backup's, files the backup does
not have are removed, its own accounts and tokens stay as they are (so DCS stays connected), and DHCP scopes go back
onto the primary only (two DHCP servers would hand out the same addresses). Technitium reloads and restarts its DNS
service: a few seconds without answers. DCS then puts back the blocklists (and asks for a download) and the apps with
their configs, and a restored primary is copied to the secondary. It is in the audit log.

### Rebuilding a resolver from scratch

1. **Install Technitium** on the new machine (or the rebuilt LXC or Pi): `curl -sSL https://download.technitium.com/dns/install.sh | sudo bash`.
   Give it the same address as before (the devices and the DHCP scope point at it).
2. **Sign in** at `http://<ip>:5380`, set the admin password, and **Create API Token** (your name at the top right).
3. **Connect** it on the Technitium page (Servers: address and the new token, as primary or secondary).
4. **Apply baseline**: forwarders, DNSSEC, the lists, the query log and the kids' app.
5. **Restore** its newest backup (Servers → Backups → Restore): its zones, allowed and blocked names, settings and,
   on the primary, the DHCP scopes and reservations come back; the kids' groups are written again by DCS.
6. On the primary, check **DHCP**: the scope is on as it was in the backup. A rebuilt secondary is equal to the
   primary after the restore's sync, or **Sync now**.

## API

`/dns/technitium/*`: see the [API reference](API.md#routing-and-dns). Reading the status, the numbers, the lists
and the groups is open to viewers; everything else is the admin's.
