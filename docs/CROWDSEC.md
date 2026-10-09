# CrowdSec × DCS — the CrowdSec page

CrowdSec reads Traefik's access log, recognises scanners and brute-forcers by how they behave, and bans them; a *bouncer* inside
Traefik then refuses banned addresses at the door, before any of your apps sees the request. The **CrowdSec** page of the
dashboard (in the sidebar, right under *DNS & Routes*) is where you deploy it, see who is knocking, ban and allow addresses, decide
how long a ban lasts, and shape the Discord messages CrowdSec sends. Everything here is also an API route ([the list](#api)).

```
  visitor ─► Traefik ─(access log)─► CrowdSec ─► decision "ban 203.0.113.7 for 4h"
               ▲                                        │
               └──────── bouncer plugin pulls the bans ─┘        └─► Discord message (optional)
```

Contents: [states](#1-the-states) · [overview](#2-overview) · [bans](#3-bans) · [alerts](#4-alerts) · [allowlist](#5-allowlist) ·
[Discord](#6-discord-alerts) · [settings](#7-settings-ban-length-escalation-simulation) · [media apps](#media-apps-a-web-client-is-not-a-crawler) · [hub](#8-hub) · [bouncers](#9-bouncers-machines-community) ·
[logs](#10-logs) · [countries](#11-countries) · [safety](#12-safety-rails) · [fleet](#13-a-vm-through-the-hub) · [API](#api) · [troubleshooting](#14-troubleshooting)

---

## 1. The states

One request (`GET /crowdsec/status`) tells the page which state CrowdSec is in, and the page shows what a person needs in *that*
state: the honest reason, the last lines of its log, and the one-click fix.

| State | What you see | One click |
| --- | --- | --- |
| **Not deployed** | An invitation with a pre-flight (Docker answers? template available? Traefik there? Discord webhook set?) and the choice of stack | **Deploy CrowdSec**: the normal template deployment, followed live; the page opens by itself when CrowdSec is healthy |
| **Defined, no container** | The stack file describes CrowdSec but the container is gone | Start the stack · Deploy again · Show the log |
| **Stopped** | Exit code and reason | Start |
| **Crash loop** | "Restarted 17 times", the exit code and the log's last lines (almost always a configuration error) | Show the log · Restart |
| **Starting** | A calm "starting" until the container reports healthy | (waits) |
| **Unhealthy** | Container runs but its health check fails | Restart · Show the log |
| **API unreachable** | Container runs and is healthy, but `cscli` cannot reach CrowdSec's local API; the bouncer keeps its cached bans | Restart · Show the log |
| **Docker unavailable** | DCS cannot talk to Docker | Check again |
| **Healthy** | The full page below | — |

The deployment does what the template always did: it puts CrowdSec next to Traefik, mounts Traefik's access log read-only,
registers the Traefik bouncer and adds its middleware to Traefik's chain (switch off *Block bans at Traefik* to only detect), and, when
a Discord webhook is known, turns the Discord alerts on. **Re-deploying keeps what you configured on the page**: when the ban settings or
the Discord message are managed by the page (their files carry a `# dcs-settings` / `# dcs-notify` marker), the deploy leaves them alone.

Things that need attention appear as banners under the numbers, each with its fix button: *Bans are not enforced at your proxy*
(no bouncer registered, or Traefik not using it), *Traefik has not asked the bouncer yet*, *CrowdSec reads no log lines*, *hub items can be
updated*, *Discord alerts are on but not working*, and so on.

## 2. Overview

The numbers at the top: engine version and health, active bans, alerts in the last 24 h (with the number of sources and countries),
bouncers and when Traefik last pulled, log lines read and understood, and the size of the community blocklist.

*What has been happening* has a window switch (**24 hours / 7 days / 30 days**; CrowdSec keeps 7 days of alerts by default and the page says so
when you ask for more) and shows detections over time, a dotted world map of where attackers are, the countries with how many
of their addresses are banned right now, the kinds of attack in plain words (*SSH brute force*, *Web probing*, *Exploit attempt*),
the busiest addresses (with a **Ban** button when not yet banned) or networks, and the latest detections. Below: **Protection**
(is Traefik enforcing the bans, one line for each thing Traefik's own files say about the bouncer, how many of your routes go through it, and your own
address), **Community** (blocklist, sharing, console) and **Engine** (version, uptime, log lines per source, hub, *Reload* and *Restart*).

**How the bouncer is wired** is read from Traefik's files, not guessed: the plugin is declared in Traefik's static configuration (name and version) and
Traefik has been restarted since; the middleware file `crowdsec-bouncer.yml` exists; `crowdsec-bouncer` is part of `traefik-chain`; the key in the file belongs to
the bouncer CrowdSec knows (a bouncer registered again after the file was written leaves a key that no longer works); when Traefik last asked CrowdSec (the plugin
reports in at least every ten minutes while it runs, so half an hour of silence counts as a problem); and the plugin's mode. Anything wrong is also a banner with the
fix behind a button (*Register again*, *Restart Traefik*). The routes line says how many routes use the chain and names the ones that **bypass** it: a route that does
not go through `traefik-chain` is never checked, so a banned address can still reach it (the same routes carry an *unprotected* badge on the DNS & Routes page).
DCS finds `traefik-chain` in the routes directory (`custom_routes/`) or, for the original layout that keeps `TraefikRoutes.yml` beside it and mounts it into the container's routes
directory, in the Traefik folder above it. The chain is read by its indentation, so a hand-written file works: any indent, entries with or without quotes, a comment after an
entry, Windows line endings, and an `@file` suffix (`traefik-chain@file` in a route counts as the chain).
A route also counts as protected when it uses a chain of your own that lists `crowdsec-bouncer`, directly or through another chain (a `media-chain`, say).
If you define the `crowdsec-bouncer` middleware yourself (in `TraefikRoutes.yml`, say), Traefik uses your definition and skips the copy DCS writes when it registers a bouncer: it keeps
the first definition of a name it reads. The page then counts the newest pull of any Traefik bouncer as *Traefik asked CrowdSec* (with your key, not DCS's), shows a note that the
middleware is defined twice, and *Register again* does not write a second copy or a second bouncer: it puts your middleware in the chain and stops. Delete DCS's copy
(`crowdsec-bouncer.yml` in the stack's routes folder) and its bouncer (`dcs-traefik-bouncer`, on the Bouncers tab) to tidy up, or keep them as a spare.

## 3. Bans

Every active ban, with a live countdown. **Search** (address, reason, country, network), filter by **kind** (addresses / networks),
**origin** (detected by CrowdSec, manual, imported, community blocklist), **country** and **reason**, sort by newest, expiring
soon, address, country or reason, hide simulated ones. Select rows to lift many at once; the info button shows the alert behind
a ban.

**Ban an address** takes an IP (IPv4 or IPv6) or a network in CIDR form and a length: 1 h · 4 h · 24 h · 7 d · 30 d · custom (`90m`, `12h`,
`10d`, `2w`, `1d12h`) · **Permanent**. CrowdSec has no ban without an end, so *permanent* is ten years and the page says so. The length
the form starts with is the *manual ban length* from Settings. A reason is optional and shows up in the list and in Discord.

The server refuses (and says why, in words):

| Refused | Why |
| --- | --- |
| your own address | it would lock you out of every site behind Traefik |
| this server's addresses, the home address DCS keeps allowed, addresses on the trusted list | the server would ban itself or the person managing it |
| private, loopback and link-local addresses | Traefik trusts your LAN, so such a ban could never block anything |
| networks wider than a /8 (IPv4) or /16 (IPv6) | a large part of the internet; a /8 to /15 is allowed after a confirmation that shows how many addresses it covers |
| an address on the allowlist | it is never banned: take it off the allowlist first |
| an address already banned for longer | lift that ban first if you want a shorter one |

A permanent ban and every bulk lift ask for confirmation. **Import** takes a list (one address or network per line with `#` comments, a CSV with a
header line `value,duration,reason`, or a JSON list of `{value, duration, reason}`), up to 2000 entries and 512 KB; every entry is checked like a
single ban and the ones that are skipped are listed with the line and the reason. **Export** downloads the (filtered) list as CSV or JSON;
cells that could be read as spreadsheet formulas are prefixed so they stay text.

Bans made by a scenario that is in *simulation mode* are marked **simulated**: they are alerts, and nothing enforces them.

## 4. Alerts

What CrowdSec detected: window (1 h · 6 h · 24 h · 7 d · 30 d), search, scenario, country, hide simulated. Each row says what it was in plain words, where it came from
(flag, network), how many requests added up, and whether the source is banned now. Open one to see the source, when it started
and stopped, what CrowdSec decided, and the requests that raised it (method, path, status, user agent, target). From there an admin can
**ban** the address, **allow it for good**, or jump to its bans.

## 5. Allowlist

Addresses CrowdSec must never ban. DCS uses the best mechanism your CrowdSec offers and tells you which:

* **Native allowlist** (CrowdSec 1.6.8 and newer, list name `dcs`): checked before every decision, also for manual bans; entries can expire (`30m`, `12h`,
  `7d`) and adding one lifts the bans it covers.
* **DCS whitelist parser** (older CrowdSec): a small parser file DCS writes; no expiry; needs a reload, which DCS does.

Your home public address is kept in the list automatically (*managed*, not removable here). The page shows the address you are
connecting from and whether it is covered, with one click to add it. Entries can be an address or a network; a network wider than a /16 asks
for confirmation.

### The home network over IPv6

At home, every phone and laptop has its own global IPv6 address (no NAT), so a visit to your public name over IPv6 does not come from the home
IPv4 address. With Cloudflare in front, that happens even for a name that only has an A record: Cloudflare answers over IPv6 and passes the
visitor's real address on. Only the IPv4 address used to be trusted, so such a visit was judged like a stranger's, and a long Jellyfin evening at
home could get you banned.

DCS now trusts the home **network** over IPv6 as well: the server's own global IPv6 address (the source address the kernel uses for the internet,
which is what the world sees) cut to **`CROWDSEC_HOME_IPV6_PREFIX`** bits, default `64` (the network of your LAN). It goes into the same whitelist
file as the home IPv4 address (`parsers/s02-enrich/dcs-whitelist.yaml`, a `cidr` entry such as `2001:db8:77:5::/64`), and the ban guard refuses a
manual ban inside it. Providers change the delegated prefix now and then: every check (every ten minutes, with each dynamic DNS round, and after
every allowlist change) looks again, replaces the old network and reloads CrowdSec only when it changed.

* Your router hands out several /64s (a /56 from the provider, one /64 per VLAN or guest network): set `56` (or `48`).
* `off` turns it off; the IPv4 home address is kept as before.
* The server has no IPv6 (IPv6 switched off in the VM, no route out): nothing is added. When its source address is a unique local one (`fd…`, NAT66),
  DCS asks the internet over IPv6 which address it is seen with, and adds nothing when nothing answers.
* `docker exec CrowdSec cat /etc/crowdsec/parsers/s02-enrich/dcs-whitelist.yaml` shows the network; `.data/crowdsec-whitelist.json` keeps it as `home_ipv6`.

## 6. Discord alerts

Every option of the Discord message is on the **Discord** tab. Nothing is hard-coded: the shipped message is only the default.

| Option | Default | What it does |
| --- | --- | --- |
| **On / off** | on when a webhook exists | send CrowdSec's decisions to Discord |
| **Webhook** | *Global* | *Global*: the webhook DCS uses for its own alerts. *Custom*: one just for CrowdSec (kept in the CrowdSec container's notification file; shown masked, never returned by the API). *Keep*: leave whatever the file has |
| **Name / avatar** | CrowdSec + the CrowdSec avatar | who the message appears from |
| **Embed colour** | automatic (by kind of attack) | or one fixed colour |
| **Mention** | nobody | a role, a user, `@here` or `@everyone`, plus extra text; a *test message never pings anyone* unless you tick it |
| **Which events notify** | new bans and simulated bans | and, optionally, detections that did not lead to a ban |
| **Filters** | none | minimum number of events; only these scenarios; ignore these scenarios |
| **Delivery** | one block per address, wait 30 s, 50 alerts a message, retry 3×, 10 s timeout | how alerts are batched and retried (see *Grouping* below) |
| **Message** | see below | title, description, footer, link, timestamp, and up to 8 embed fields (name, value, inline) |
| **Daily summary** | 08:00 | the last 24 hours in one message (see below); `CROWDSEC_DIGEST_HOUR` |

**Grouping.** CrowdSec hands its alerts over in batches: what arrives within the wait (30 s), or at once when 50 have piled up. Each batch is **one Discord message
with one block per source address**: a scanner that fires 50 alerts in a few seconds is one block, not 50. The block says where it came from
(`🛡️ 194.26.135.7 · 🇷🇺 RU · Petersburg Internet Network ltd.`), how many attempts over how long and the ban (`50 attempts in 7s → banned 4 hours`),
every attack it tried with how often, the most frequent first (`Exploit attempt CVE-2025-29927 ×41 · Exploit attempt CVE-2024-4577 ×4 · Attack blocked appsec-vpatch ×2`,
six, then "+k more"), the hosts it aimed at and its first and last request path, and the CTI / AbuseIPDB links. The colour is the most severe attack's.
Discord takes 10 blocks and 6000 characters a message: more than 10 addresses make 9 blocks and a tenth that lists the rest, and every part is cut to fit.
*Group by alert* gives the old one-block-per-alert layout. Note CrowdSec's own timing: after a quiet spell the **first** alert of a burst goes out within a second
(CrowdSec flushes as soon as the wait has passed since its last message), the rest of the burst follows in one message after the wait.
Settings saved by an older DCS keep working: an untouched message and delivery move to these defaults; a message you wrote stays yours. A notification file
written by an older DCS is pointed out on the tab: saving (even without a change) writes the new layout and keeps the webhook.

**Daily summary.** Once a day at `CROWDSEC_DIGEST_HOUR` (this server's local time, default 8; `off` turns it off; the Discord tab sets it) one message sums up
the last 24 hours: attempts and addresses, the top five addresses with their countries, the top five attacks, and the bans (addresses banned, already free
again, lifted by hand, banned now, plus the community blocklist). It goes to the webhook of the alerts, only while they are on, and once a day: a restart does
not send it twice (`.data/crowdsec/digest.json`); when Discord refuses it, it is tried twice more, ten minutes apart. **Send now** on the tab posts it at once.

The message is text with placeholders like `{ip}`, `{country_tag}` or `{label}`; the editor has a picker that inserts them, a **live preview** that shows the embed as
Discord will draw it (rendered by the server with the same code that sends the real message, so what you see is what arrives), a sample selector (a burst from one address, three addresses at once, web probing,
SSH, exploit, manual ban, simulation), and **Send test message**, which really posts to the webhook and reports what Discord answered. The last test, the last
save and recent delivery errors are shown. **Reset to the shipped message** puts the default back and keeps the webhook and the on/off switch.

| Placeholder | Meaning |
| --- | --- |
| `{ip}` `{scope}` `{range}` | the address (or network), `Ip`/`Range`, the network it belongs to |
| `{country}` `{flag}` `{country_tag}` | country code, Discord flag emoji, " :flag_nl: NL" (empty when unknown) |
| `{as_number}` `{as_name}` `{as_tag}` | autonomous system number, who runs the network, " · Name" (empty when unknown) |
| `{scenario}` `{scenario_short}` `{label}` | full scenario name, without the `crowdsecurity/` prefix, and the plain-language attack type |
| `{events}` `{alert_id}` `{message}` `{sim_tag}` | number of log lines, CrowdSec's alert number and one-line summary, " (simulation)" |
| `{attempts}` `{span}` `{alerts}` `{scenarios}` | "50 attempts in 7s" (or "one request"), the time from first to last request, the number of alerts, every attack with its count |
| `{ban}` `{ban_tag}` | the longest decision in words ("banned 10 years", "captcha for 4 hours", "would be banned 4 hours (simulation)"), " → **…**" |
| `{flag_emoji}` `{source_tag}` | the flag as an emoji (works in titles), " · 🇳🇱 NL · IP Volume inc" |
| `{targets}` `{targets_line}` `{last_path}` `{last_path_code}` `{requests_line}` | all hosts attacked (three, then "and k more"), the same as a line of its own, the last path, a "First … · last …" line |
| `{decision}` `{duration}` `{for_duration}` | ban, how long, " for 4h" |
| `{origin}` `{origin_tag}` | where the decision came from (detection or manual) |
| `{target}` `{target_tag}` `{path}` `{path_code}` `{user_agent}` | the site attacked, the first request's path and user agent |

With grouping by address every placeholder describes the address's block: `{events}` and `{attempts}` add up its alerts, `{label}` and `{scenario}` are the attack it
tried most, the decision is the longest one.
| `{machine}` `{machine_tag}` `{domain}` `{server}` | the engine, your domain, this DCS server's name |
| `{time}` | Discord's live "x minutes ago" stamp |
| `{cti_url}` `{abuseipdb_url}` | the address on CrowdSec CTI and on AbuseIPDB |

User text never reaches the generated files as code: the message is compiled into string literals and variables for CrowdSec's template engine, so quotes, backslashes, `{{ }}`
and line breaks in a message can change nothing but the message. The webhook is admin-only and masked everywhere else. CrowdSec cannot announce a lifted ban; unbans made from DCS raise
the `crowdsec_unban` event for the *Notifications* page instead.

## 7. Settings: ban length, escalation, simulation

**How long CrowdSec bans** (the ban profile): the default length for an address (default **4 hours**), for a whole network, an optional **repeat-offender escalation** (each new ban
of the same address lasts longer than the last, up to a cap; default off, cap 30 days), **per-scenario lengths** (up to 12 rows: SSH brute force for a day, known exploits for a week; the
first matching row wins, a `*` at the end matches a prefix), and the length a manual ban gets when nobody chooses one. A sentence at the top says what the result is in plain words.

Saving is safe: DCS builds the new file, has **CrowdSec itself validate it** in a scratch directory of the container, backs the current file up, writes it, restarts CrowdSec, waits until it is
healthy and the local API answers, **reads the file back**, and if anything fails puts the previous file back and restarts again, telling you which step failed. One apply runs at a time.
If someone edited `profiles.yaml` by hand (*custom*), the page shows the file, and replaces it only after you confirm (a backup is kept). Backups are listed.

**The Traefik bouncer plugin** (the same tab; needs the bouncer registered). The plugin is the part inside Traefik that refuses banned visitors; these are its own
settings, written into its middleware file `crowdsec-bouncer.yml` with the same care as the ban profile (checked first, written atomically, the old file kept, a marker line
so registering the bouncer again or a re-deploy keeps them) - Traefik reloads the file by itself within seconds:

| Setting | Default | What it does |
| --- | --- | --- |
| **Mode** | live | *live*: Traefik asks CrowdSec about a visitor the first time it sees one and remembers the answer. *stream*: Traefik downloads the whole ban list every few seconds and decides on its own (a new ban reaches the door that many seconds later, and it keeps working for a while if CrowdSec is down) |
| **Update interval** | 60 s (10 s to 1 h) | stream only: how often the ban list is downloaded |
| **Remember an answer for** | 10 s (10 s to 1 h) | live only: how long a clean verdict is cached; shorter means a new ban bites faster (and a lifted one is noticed sooner). Installs from before keep what they have (60 s then) |
| **Timeout** | 10 s (1 to 60 s) | how long Traefik waits for CrowdSec before it gives up on one question |
| **Status a banned visitor gets** | 403 (400 to 599) | 403 forbidden is the usual one; 429 tells well-behaved clients to slow down |
| **Log level** | INFO | how much the plugin writes in Traefik's log |
| **Visitors that are never checked** | your LAN, your home address | `clientTrustedIPs`: the LAN of your Traefik (`TRAEFIK_TRUSTED_LAN`) is always in; *never check my home address* (on by default when you save) keeps the address DCS follows (dynamic DNS) in the list and moves it when it changes |
| **Proxies whose forwarded address is believed** | Cloudflare's ranges + your LAN | `forwardedHeadersTrustedIPs`: a CDN or proxy in front of Traefik. Only these may say who the real visitor is |

Only a safe subset is offered: the modes *none*, *alone* and *appsec* and the plugin's Redis and AppSec options stay in the file, untouched, for people who need
them. Networks wider than a /8 (IPv4) or /16 (IPv6) are refused in both lists: a list that says "trust everyone" would switch the bouncer off.

**Simulation mode**: scenarios that only alert and never ban, per scenario or for the whole engine (*watch only*, with a warning that nothing is blocked while it is on).

### Media apps: a web client is not a crawler

One page of Jellyfin's web client makes dozens of API and artwork requests in a second, and some of them come back 404 (an item without a logo). CrowdSec's generic HTTP scenarios
(`http-crawl-non_statics`, `http-probing`) read that as a crawl and as probing, and ban the person watching. **`CROWDSEC_MEDIA_APPS`** names the backends that are media apps (default
`jellyfin`); for them DCS keeps one more parser file, `parsers/s02-enrich/dcs-media-apps.yaml`, beside the whitelist's. The file is DCS's: it is written when it differs, removed
when the setting is empty, and CrowdSec reloads (a reload, not a restart) only when it changed. DCS looks every ten minutes, with the check that keeps your home address allowed, and
reads the setting from `.env` each time.

**Which requests are the app's.** Traefik's access log names the backend by its address, and that address is the container's name only when this server's Traefik reaches the
container by name (`http://jellyfin:8096`). On a hub, a route into a VM of the fleet reaches the app at the VM's address (`192.168.1.202:8096`), and a route made by Docker labels at
the container's address, so matching the address alone missed them: a friend watching Jellyfin in a VM through the hub was judged like a scanner. DCS therefore also matches the
**router** that took the request, which is in every line of the log. The routers are found by DCS each time it writes the file:

* each name and *name*`-router` (the routes DCS writes, the usual Docker labels such as `jellyfin@docker`);
* every router of this server's route files whose service's server is one of the names (a route renamed to `watch-router` whose server is still `http://jellyfin:8096`);
* for every member of the fleet, `<member>-<name>-dcs`: a VM's route file is named after its service, and the hub's `fleet-members.yml` prefixes the member. When a new VM's
  routes arrive, the hub rewrites the file right away.

For a listed backend CrowdSec stops counting:

* a `GET` or `HEAD` the app **answered** (2xx or 3xx), unless its address, query included, contains `..`, `%2e`, `%00`, `%5c` or `%252`: a path that tries to leave the web root is never ignored
  (the same holds for the three rules below);
* a `GET` or `HEAD` answered 404 for **missing media**: the picture of an item, a person, a studio, a genre, an artist or a user (`/Items/<id>/Images/<type>`, `/Users/<id>/Images/Primary` …,
  with or without the `?fillHeight=…` the client adds), a song's lyrics (`/Audio/<id>/Lyrics`), a subtitle stream, a trickplay strip; an optional base URL such as `/jellyfin` in front;
* a `GET` or `HEAD` the **app itself refused with 403** (the request reached it: the log has the backend's address). That is a signed-in user asking for what the account may not see: a page of
  Jellyfin's web client asks a user who is not an administrator for admin-only plugin and server settings (`/Plugins`, `/PluginUpdateNotifier/summary`, `…/admin/…`), which
  `http-probing` and `http-admin-interface-probing` took for probing. An anonymous scanner gets 401 or 404 from these apps;
* a **403 of the proxy itself** on the app's router (no backend address in the log: the CrowdSec bouncer, a geoblock). A client that is banned keeps polling, and every refusal is a 403:
  counting them banned the person a second time (with escalation, for longer). The ban that refused them stays.

What it deliberately does **not** do: everything else is judged exactly as before.

* **404, 400 and 401 answers still count** (missing media apart), and so does a 403 to any other method. A scanner asks for things that are not there, so it is banned as before; a login brute
  force (`POST`, 401) and a session that expired and is refused a hundred times in a row are counted too.
* **Other methods** (`POST`, `PUT`, `DELETE` …) and **every other backend**, routed by Traefik or not, are untouched. The match is on the backend Traefik routed the request to (its address
  or its router in the access log), not on anything the visitor sends.
* **Path traversal** keeps its scenarios (the first bullet above).

One consequence to know: a request the file ignores reaches *no* scenario, not only the two generic ones. A client that only asks for what the app serves is not banned for how much it asks,
nor for its user agent; the moment it asks for something the app refuses, which is what scanning is, it is counted like everyone else.

**Another media app.** Add the host of its service in Traefik's route (the part of `http://plex:32400` before the colon): `CROWDSEC_MEDIA_APPS=jellyfin,plex`. Names are letters, digits, `-`, `_`
and `.`, in any case; anything else is ignored. The rule for missing media knows Jellyfin's (and Emby's) addresses only; the other three rules apply to every listed app.
**Turn it off** with `CROWDSEC_MEDIA_APPS=` (empty): the file goes at the next check.

**Is it working?** `docker exec CrowdSec cscli parsers list` shows `custom/dcs-media-apps`, and `docker exec CrowdSec cscli metrics show whitelists` counts what it ignored (the *Whitelisted*
column). The tuning is tested against the real CrowdSec by `tests/crowdsec-media-apps.sh` (opt-in: it replays synthetic access logs through the CrowdSec image, with and without the file).

## 8. Hub

The hub is CrowdSec's library of **collections** (bundles), **scenarios** (attack detectors) and **parsers** (log readers). See what is installed and what has an update, install a suggested
bundle for a Traefik + SSH server (each with a sentence on what it does), search everything the hub offers, remove items (with a warning for the ones DCS's detection relies on),
**check for updates** and **upgrade all**. CrowdSec reloads after every change.

## 9. Bouncers, machines, community

* **Traefik enforcement**: is Traefik running, is the DCS bouncer registered, is its middleware file there, is it in Traefik's chain, when did it last pull. **Register the Traefik bouncer**
  makes a fresh key, writes the middleware file and adds it to the chain (safe to repeat: a chain that lists the middleware already is not touched; a new entry goes after
  `cloudflarewarp` or `real-ip` when the chain starts with one, because a bouncer that runs before them would judge Cloudflare's addresses instead of the visitor's; the file is
  rewritten in place, so a stack that bind-mounts it as a single file keeps seeing it).
* **Bouncers**: every program that enforces bans (Traefik's plugin, a firewall bouncer …): type, version, address, last pull. Add one (the API key is shown **once**, with a copy button)
  or delete one (its key stops working at once). A bouncer whose key Traefik's `crowdsec-bouncer` middleware still holds is not deleted: the answer is 409 *"Traefik's
  crowdsec-bouncer middleware still uses this bouncer; register again from the Bouncers tab instead of deleting it"*, because Traefik would keep asking with a key CrowdSec
  no longer knows and the plugin fails open. CrowdSec never shows a key again, so the match is by name: `dcs-traefik-bouncer` while any routes file defines the middleware,
  and every name DCS recorded in `.data/crowdsec/traefik-bouncers.json` when it wrote one. `DELETE /crowdsec/bouncers/{name}?force=true` (or `{"force": true}`) deletes it
  anyway. The connections CrowdSec files under `name@ip` are CrowdSec's own: it refuses to delete them, and the answer is 409 with its reason.
* **Machines**: the engines that report to this CrowdSec (this container's agent, others you enrolled).
* **Community**: whether the community blocklist is pulled, whether your detections are shared, whether the machine is enrolled in the CrowdSec Console. The status is read
  locally and never logs in at CrowdSec's Central API: `cscli capi status` and `cscli console status` each make a fresh login, and the central service pauses an engine
  that logs in too often (it then answers `403 Forbidden` to its metrics, signals and blocklist pull for an hour or more). DCS reads what the engine already logs about its
  own exchanges with the central service, its config files and its start time, and names one state: **ok**; **paused** (403s that began less than two hours ago, right
  after a start or reload, or while DCS itself logged in within the hour: it recovers on its own, and registering again would only extend it, so *Register again* and
  enrolling answer "paused" unless forced); **refused** (403 for two hours or more with nothing accepted in between: *Register again*, then enrol in the console again if it
  was enrolled); **unknown** (nothing logged yet); **disabled** (no `online_client`, e.g. `DISABLE_ONLINE_API`). *Check now* (`POST /crowdsec/community/check`) is the one
  real login, at most once per 10 minutes. If registering is refused with 403 as well, it is the address that is refused; that usually clears by itself. Local detections,
  bans and alerts keep working throughout; only the shared blocklist is missing.

### Push bans to Cloudflare

When your sites are proxied by Cloudflare (the orange cloud), a scanner CrowdSec banned still reaches Cloudflare, Cloudflare still forwards
it, and Traefik answers it 403: it keeps costing a request at your server and keeps feeding CrowdSec new detections. **Push bans to
Cloudflare** (a switch on the Bouncers tab, next to Traefik enforcement) has Cloudflare refuse those addresses at its edge, before
anything is forwarded. Traefik's bouncer stays where it is: it still guards the server for anything that does not come through
Cloudflare.

**What it makes at Cloudflare**, and nothing else:

| What | Where | Name |
| --- | --- | --- |
| one IP list per account, holding the bans | Manage Account → Configurations → Lists | `dcs_crowdsec_bans` |
| one WAF custom rule per zone, action **Block**, the zone's first custom rule | the zone → Security → WAF → Custom rules | *DCS Orchestrator: block CrowdSec bans* (`ip.src in $dcs_crowdsec_bans`, ref `dcs_crowdsec_bans`) |

and in CrowdSec a bouncer, `dcs-cloudflare-bouncer`, whose key DCS keeps (`.data/crowdsec/cloudflare-bouncer.key`, 600). The zones are
those of your domains (`PROXY_DOMAIN` and `PROXY_DOMAINS_EXTRA`; a domain below its zone, such as `lab.example.com`, protects
`example.com`), or the ones `CLOUDFLARE_BOUNCER_DOMAINS` names. A blocked request shows in the zone's Security → Events under that rule.

**How it stays in step.** Every 30 s (`CLOUDFLARE_BOUNCER_INTERVAL`) the API's background loop asks CrowdSec's local API, with the
bouncer's own key, for the active bans (`GET /v1/decisions?type=ban&scopes=ip,range&origins=…`; CrowdSec records the pull, so the bouncer
shows a last pull like any other). Only bans count (a CAPTCHA decision is not one), only addresses and networks (a country is not an
address), only your own bans by default: CrowdSec's detections, the bans of this page and of an import, the console's (origins
`crowdsec`, `cscli`, `cscli-import`, `console`). The list never holds a private address, this server's addresses, your home address or
anything on the allowlist (the same guard as a ban from the page), nor a network wider than Cloudflare takes (IPv4 /8, IPv6 /12). The
newest bans come first; past `CLOUDFLARE_BOUNCER_CAPACITY` (10,000) the oldest are left out and the status says how many. The list's
items are replaced only when the bans changed (one call, followed until Cloudflare has stored them). Every 5 minutes DCS also reads the
list and the rules back and repairs what was changed at Cloudflare: a rule that was deleted is made again (as the first custom rule), a
rule switched off or turned into *Log* blocks again, a list emptied or deleted by hand is filled again. When CrowdSec does not answer,
nothing is pushed: Cloudflare keeps refusing the addresses it holds. When CrowdSec no longer knows the bouncer's key (its database was
reset), DCS registers the bouncer again by itself. The bouncer is not deleted from the Bouncers list while the switch is on (409: the
switch is the way).

**Why not CrowdSec's own Cloudflare bouncer.** `crowdsecurity/cloudflare-bouncer`, the one that kept an IP list, is archived and CrowdSec
lists it as deprecated: it writes Cloudflare's Firewall Rules and Filters APIs, which Cloudflare stopped supporting on 2025-06-15. Its
successor, `crowdsecurity/cloudflare-worker-bouncer`, puts a Cloudflare Worker in front of every request: on the free plan that is 100,000
requests a day (1,000 a minute), its routes are created *fail closed* (a scanner that burns the quota takes your sites down with error
1027) and Cloudflare has no API to change that. A list and a WAF rule cost no quota, add no latency and hold whatever the traffic, so DCS
keeps them itself, with the current Lists and Rulesets APIs.

**The token.** Its own setting, `CLOUDFLARE_BOUNCER_TOKEN`: the DNS token (`CF_DNS_API_TOKEN`) is never used for it. Make it at
dash.cloudflare.com → My Profile → API Tokens → Create Token → *Custom token* (an account-owned token from Manage Account → API Tokens works
too), with exactly these rights:

| Group | Item | Level | For |
| --- | --- | --- | --- |
| Account | Account Filter Lists | Edit | the list of banned addresses |
| Zone | Zone WAF | Edit | the custom rule that blocks the list |
| Zone | Zone | Read | finding the zones of your domains |

Account Resources: the account of your zones; Zone Resources: those zones (or all zones). Paste it into the switch's dialog: DCS checks
it before anything is made (`GET /user/tokens/verify`, the zones, the account's lists, each zone's custom rules) and refuses with the
exact right that is missing, the domain without a zone, or the free plan's limit that is reached, and nothing is changed. A token you
already keep on the Secrets page under the name `CLOUDFLARE_BOUNCER_TOKEN` is used when the dialog's field is left empty (the dialog says
*Using the secret CLOUDFLARE_BOUNCER_TOKEN*); a token pasted there replaces that secret. It is stored
encrypted in the secrets store (`.secrets/CLOUDFLARE_BOUNCER_TOKEN.enc`, 600; the Secrets page lists it), goes to curl on its standard
input (never on a command line) and is never logged or sent back. A value in the root `.env` (`CLOUDFLARE_BOUNCER_TOKEN=${SECRETS_X}` or
the token itself) is read when no secret is stored.

**The free plan.** An account's limits follow its highest plan:

| Plan | Custom lists | Items over all lists | Custom rules per zone |
| --- | --- | --- | --- |
| Free | 1 | 10,000 | 5 |
| Pro, Business | 10 | 10,000 | 20, 100 |
| Enterprise | 1,000 | 500,000 | 1,000 |

On a free account the list is the account's one custom list: if another list holds it, the switch says which and stops. Five custom rules
in a zone already: the same. Your own bans are a few hundred addresses at most, far below 10,000. The community blocklist (the
*community* option, `CLOUDFLARE_BOUNCER_COMMUNITY=true`) is tens of thousands of addresses: it is added after your own bans and cut at the
capacity (the newest first), so it never pushes one of yours out.

**Status.** The Bouncers tab shows the switch, its health (on and in step, starting, not in step for over 10 minutes, or the error in plain
words: the token was rejected, a zone was not found, a right is missing, the list or rule quota was reached, the list is full, CrowdSec
does not answer), how many addresses are on Cloudflare's list (read back from Cloudflare at most once a minute), the zones, the last pull
and the last sync, and the bouncer's registration. *Sync now* runs one at once. When the switch is on and the last good sync is older than
10 minutes, the CrowdSec page shows an issue and the dashboard's *Needs your attention* lists it.

**Turning it off cleanly.** Switch it off on the Bouncers tab. The sync stops at once and the bouncer is deleted in CrowdSec. The dialog
asks what to do at Cloudflare:

* **Remove the list and the rule** (recommended): the custom rule is deleted from each zone, then the list (a list a rule still uses
  cannot be deleted). Your own lists and rules are never touched: DCS finds its own by name and ref.
* **Leave them**: they stay as they are, frozen with the last bans, which then never expire at Cloudflare. *Remove them from
  Cloudflare* on the tab (or `POST /crowdsec/cloudflare/disable {"cleanup": true}`) does it later.

The token stays stored, so turning it on again is one click; *Forget the token* (`"forget_token": true`) deletes it. By hand: delete the
custom rule *DCS Orchestrator: block CrowdSec bans* in each zone, then the list `dcs_crowdsec_bans`, and the bouncer with
`cscli bouncers delete dcs-cloudflare-bouncer`.

| Setting (root `.env`) | Default | What |
| --- | --- | --- |
| `CLOUDFLARE_BOUNCER_ENABLED` | `false` | the switch (set by the page) |
| `CLOUDFLARE_BOUNCER_TOKEN` | — | the token, kept as the secret of that name |
| `CLOUDFLARE_BOUNCER_CAPACITY` | `10000` | at most this many addresses on the list (1–500000) |
| `CLOUDFLARE_BOUNCER_COMMUNITY` | `false` | also the community blocklist, within the capacity |
| `CLOUDFLARE_BOUNCER_DOMAINS` | all of this server's domains | the domains whose zones block the list, comma separated |
| `CLOUDFLARE_BOUNCER_INTERVAL` | `30` | seconds between two syncs (10–3600) |
| `CROWDSEC_LAPI_URL` | where Docker publishes CrowdSec's port 8080 | CrowdSec's local API, for a CrowdSec DCS did not deploy |

`tests/smoke.sh` checks all of this against a stand-in of Cloudflare's API (`tests/mock-cloudflare-waf.py`); `tests/cloudflare-bouncer-live.sh`
runs it against a real CrowdSec (in a sandbox: it refuses to run where a CrowdSec container exists).

## 10. Logs

The tail of the CrowdSec container's log: level (all / warnings / errors), text filter, 100–500 lines, an option to include the noisy API request lines, auto-refresh, copy and download.

## 11. Countries

The country of every ban and alert comes from CrowdSec's GeoIP and is shown everywhere as a flag (where your system draws flag emoji; otherwise a two-letter code chip) and the country name.
The overview ranks countries over 24 h, 7 d or 30 d, and the bans and alerts can be filtered by country. **There are no country-wide bans**: the Traefik bouncer enforces IP addresses and networks
only, so the page never offers one and says so.

## 12. Safety rails

* Viewers read everything but the webhook and the raw profile file; every change needs an admin. Each change is written to the audit log.
* Everything the API sends to Docker is a separate argument, never a shell string; addresses, names, durations and messages are validated before they get anywhere near a command or a file.
* Slow calls have timeouts and a short cache, so an open page adds almost no load; the page refreshes about every 15 s and pauses while the tab is hidden.
* Your own address, this server and the home address can never be banned from the page.

## 13. A VM through the hub

On a hub, the *Server* chips at the top of the page choose the hub or one VM; every call goes through the fleet proxy to that VM's own CrowdSec and its own DCS decides with its own role checks.

**The routes of your VMs are protected by the hub's bouncer.** A VM's service is published through the hub's Traefik (the hub writes the VM's routers into
`fleet-members.yml`), and every one of those routers gets the hub's `traefik-chain` (and `compress-gzip`), the chain that holds `crowdsec-bouncer` once the hub's bouncer
is registered. So the hub's CrowdSec decides for the traffic to a VM's services too: ban an address on the hub and it is refused at the hub's door, whichever VM it
was after. A VM that runs its own Traefik gets the same from its own chain. The routes list of DNS & Routes marks a route that does *not* use the chain (a hand-written
route file without `traefik-chain`) as **unprotected**, and the Protection panel counts them; on a hub without any chain (no Traefik template) a VM's routes have none
and read as unprotected too.

## API

Viewers may `GET` and may draw the Discord preview (it only renders, it never sends); changes need an admin. The generated reference is [docs/API.md](API.md); the CrowdSec routes:

| Route | What |
| --- | --- |
| `GET /crowdsec/status` | the state, the fixes, the numbers, the issues |
| `GET /crowdsec/decisions` · `POST` · `DELETE /crowdsec/decisions/{value}` · `POST …/delete` · `POST …/import` · `GET …/export` | bans |
| `GET /crowdsec/alerts` · `GET /crowdsec/alerts/{id}` | detections |
| `GET /crowdsec/metrics?window=24h\|7d\|30d` | timeline, countries, scenarios, sources, networks, map points |
| `GET /crowdsec/allowlist` · `POST` · `DELETE /crowdsec/allowlist/{value}` | never-ban list |
| `GET /crowdsec/bouncers` · `POST` · `DELETE …/{name}` · `POST …/register-traefik` · `GET /crowdsec/machines` | enforcement |
| `GET /crowdsec/cloudflare` · `POST …/verify` · `…/enable` · `…/disable` · `…/sync` · `…/settings` | [push bans to Cloudflare](#push-bans-to-cloudflare): the status; check a token; on (`{token, capacity, community, domains}`); off (`{cleanup, forget_token}`); sync now; the settings |
| `GET /crowdsec/settings` · `PUT` | ban profile |
| `GET /crowdsec/plugin` · `PUT` · `POST /crowdsec/traefik/restart` | the Traefik bouncer plugin's settings, and a Traefik restart (it loads a declared plugin only as it starts) |
| `GET /routes` | every route now says `crowdsec`: `protected`, `bypass` or `off` (CrowdSec is not set up on the proxy) |
| `GET /crowdsec/simulation` · `POST` | alert-only scenarios |
| `GET /crowdsec/notifications` · `PUT` · `POST …/preview` · `POST …/test` · `POST …/reset` | the Discord editor |
| `POST /crowdsec/notifications/digest` · `PUT …/digest` | send the daily summary now; its hour (`{"hour": 8}` or `"off"`) |
| `GET /crowdsec/hub` · `POST …/update` · `…/upgrade` · `…/install` · `…/remove` | the hub |
| `GET /crowdsec/logs` · `GET /crowdsec/community` · `POST …/community/check` · `POST …/community/register` · `POST /crowdsec/console/enroll` · `POST /crowdsec/service` | log, community (read locally; check is the one login, every 10 min at most), start/restart/reload |

## 14. Troubleshooting

| Symptom | Look at |
| --- | --- |
| *Bans are not enforced at your proxy* | the banner's button registers the bouncer; Traefik needs the plugin in its static config (DCS adds it and restarts Traefik once if it is missing) |
| Every route behind Traefik answers 404 after a change | Overview → Protection → *How the bouncer is wired*: the plugin must be declared in Traefik's static configuration and Traefik restarted since (*Register again* declares it, *Restart Traefik* loads it); a key that is older than the bouncer makes the bouncer useless, not the routes 404 |
| A route is *unprotected* | it does not use `traefik-chain`: add the chain to the router's middlewares (the routes DCS writes do this by themselves), then reload |
| Bans exist but nothing is blocked | Overview → Protection: is the bouncer pulling? A bouncer that has never pulled means no request has gone through the middleware yet, or the middleware is not in the chain your services use |
| *Log lines: 0 read* | CrowdSec reads Traefik's access log from the shared logs folder; check Traefik writes it (`accessLog` in `traefik.yml`) and that the volume is mounted |
| You banned yourself | Dashboard → *Protection* card → **Unban me**, or lift the ban from the list; the guard normally prevents it |
| Somebody was banned just for using Jellyfin (or another media app) behind Traefik | The alert says `http-crawl-non_statics`, `http-probing` or `http-admin-interface-probing`: [media apps](#media-apps-a-web-client-is-not-a-crawler); `CROWDSEC_MEDIA_APPS` must name the app's service host, and a route written by hand must lead to it by name or be called *name*`-router` |
| You were banned at home, on your own server | Your device went out over IPv6: [the home network over IPv6](#the-home-network-over-ipv6) (the server needs IPv6 itself to know the home prefix; `56` when the router hands out several /64s) |
| Discord stays silent | Discord tab: status card (*wired*, *plugin active*, *working*), **Send test message**, recent delivery errors; the webhook must be a `https://discord.com/api/webhooks/…` URL |
| A settings change failed | the page says which step; the previous file is put back automatically, so CrowdSec is never left on a bad file |
| CrowdSec restarts in a loop | Show the log: almost always a configuration error in a file that was edited by hand |
| Banned scanners still reach Traefik through Cloudflare | Bouncers tab → [Push bans to Cloudflare](#push-bans-to-cloudflare); check the zone's Security → Events for *DCS Orchestrator: block CrowdSec bans* |
| *Cloudflare is not getting the bans* | the Bouncers tab says why (a right of the token, the list or rule quota, CrowdSec not answering); *Sync now* tries at once. Cloudflare keeps refusing the addresses it already holds meanwhile |
