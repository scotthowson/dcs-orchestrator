<sub>[← Documentation](README.md)</sub>

# Technitium DNS: the home's resolver, run from DCS

[Technitium DNS Server](https://technitium.com/dns/) answers every name the house asks for: it blocks ads,
trackers and what the children should not reach, forwards the rest encrypted, and keeps a log of who asked
what. DCS runs it from **Security → Technitium** (also linked from DNS & routes), so Technitium's own console is
needed once: to make an API token.

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
5. **Move DHCP** from the ISP router to Technitium: in Technitium's console, **DHCP → Scopes**, a scope for
   `192.168.2.0/24` (the router as gateway, the range the router used), **DNS servers 192.168.2.53, 192.168.2.207**,
   reserved leases for the consoles and the tablets (stable addresses are what the kids' groups follow). Turn the
   router's DHCP off, then on the scope **Enable**. Devices pick it up as their leases renew (or after a reconnect).
   With Technitium serving DHCP, the top clients carry their device names.

## The page

- **Overview**: both servers (reachable, version, blocking, in sync), queries and blocked over the last hour, day
  or week, the top clients, domains and blocked names (**Allow** on a blocked one), **Pause blocking** for 5, 15
  or 60 minutes on both (it comes back by itself; **Resume** ends it early), **Sync now**.
- **Kids**: one card per group (a child, or all the boys) with its devices, its category lists, its bedtime and
  **Pause bedtime 30 min**. Categories: adult content, gambling, social networks, VPNs/proxies/other DNS,
  and search engines without SafeSearch (Hagezi's lists; Hagezi has no dating list, so none is offered).
- **Activity**: one device's recent queries from both servers, the blocked ones marked, with Allow / Block.
- **Lists**: the blocklists, and the names allowed or blocked for everyone.

A viewer sees the page read-only and does not see a device's queries.

## How the groups work

DCS keeps the groups in `.data/technitium/groups.json` and writes them into the Advanced Blocking app's config on
both servers (DCS owns that config: what was set for the app in Technitium's console is replaced). A device is an
address (or a small network such as `192.168.2.48/29`); a device is in one group at a time; a device in no group
gets the house's blocking alone.

**Bedtime** blocks every name for the group's devices (`blockedRegex: ["."]`), except this server's own domains,
from *from* to *to* on the chosen days (a night that starts on Sunday ends on Monday morning). The API's minute
clock (the automation loop: `AUTOMATIONS_ENABLED` must stay `true`) works out which groups are in bedtime and
writes the config only when that changes, with a line in the audit log each time. Its state is
`.data/technitium/state.json`, so a restart of the API changes nothing. **Pause bedtime** lifts it for 30 minutes.

## SafeSearch and YouTube: the whole house

Technitium cannot do SafeSearch per group: the Advanced Blocking app answers a blocked name only with fixed
addresses from a downloaded list, never with another name. So it is a switch for the house: each forced name
(`www.google.com`, `www.bing.com`, `duckduckgo.com`, `www.duckduckgo.com`; for YouTube `www.youtube.com`,
`m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com`) gets a
*Forwarder* zone of its own whose apex is an ANAME to the safe name (`forcesafesearch.google.com`,
`strict.bing.com`, `safe.duckduckgo.com`, `restrict.youtube.com` or `restrictmoderate.youtube.com`); every
other name under it resolves as usual. Turning it off removes those zones (a zone of the same name you made
yourself, of another type, is left alone). For the kids, add *Search engines without SafeSearch* to their group.

## Keeping the secondary in step

After every change DCS makes, and on **Sync now**, the secondary gets the primary's forwarders and their
settings, blocklists, cache size, the allowed and blocked names, the apps (installed when missing) with their
configs, and the forced SafeSearch zones. The status compares a fingerprint of all of that on both
(`in_sync`). DHCP scopes and anything else made in Technitium's console are not copied.

## API

`/dns/technitium/*`: see the [API reference](API.md#routing-and-dns). Reading the status, the numbers, the lists
and the groups is open to viewers; everything else is the admin's.
