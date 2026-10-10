# Security

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/scotthowson/dcs-orchestrator/security/advisories/new)
rather than in a public issue. Include the version (`cat VERSION`), how to reproduce, and what an
attacker gains. You will get an acknowledgement within a few days.

## What the API protects, and what it does not

DCS manages a Docker host. An **admin** account is, by design, equivalent to shell access on that
host: admins can deploy compose files, run commands in containers, edit `.env`, install plugins and
open the web terminal. The security model therefore concentrates on three things:

1. **Nobody gets in without an account.** Authentication is mandatory whenever the API listens on
   anything other than loopback. `API_AUTH_ENABLED=false` is ignored on a non-loopback bind unless
   `API_INSECURE_NO_AUTH=true` is also set, and the server prints a warning when it is.
2. **A fresh install cannot be hijacked.** Until the first admin account exists, only the setup
   endpoints (`/setup/status`, `/setup/defaults`, `POST /auth/setup`) and `GET /version` answer;
   every other route returns `401`. The same lockdown applies after a factory reset.
3. **A viewer is a viewer.** The `user` role can read operational data and manage its own session
   and profile. Every route that changes the system, executes code or exposes secrets requires
   `admin`. The router enforces this centrally (`_api_route_allowed`); handlers keep their own
   checks as defence in depth. The complete map is in [docs/API.md](docs/API.md).

### Accounts and sessions

- Passwords are hashed with PBKDF2-SHA256 (100,000 iterations, per-user salt) and compared in
  constant time; secrets are passed to the hashing helper through the environment, never argv.
- Session tokens are 256-bit random values with a configurable expiry; a new login revokes older
  sessions when `API_SINGLE_SESSION=true`. At rest only a SHA-256 digest is kept — a leaked copy
  of `tokens.json` or `terminal-sessions.json` cannot replay a session. Optional TOTP (RFC 6238)
  two-factor login.
- Registration is invite-only; invites expire and are single-use.
- Login attempts are rate-limited per client address (`API_MAX_LOGIN_ATTEMPTS`,
  `API_LOCKOUT_DURATION`) and every request is rate-limited (`API_RATE_LIMIT` per
  `API_RATE_WINDOW`). Behind the DCS-UI container (or any proxy listed in `API_TRUSTED_PROXIES`)
  the real client address is taken from `X-Forwarded-For`, walked from the right so that a client
  cannot spoof its own address.

### Input handling

- Every path parameter is validated in the router before a handler runs (stack names, container
  names, template names, snapshot ids, image references, subdomains, version ids).
- `.env` files are read as **data**, never sourced: only `KEY=value` lines are accepted, values are
  literal, and a fixed list of shell/loader variables (`PATH`, `LD_PRELOAD`, `BASH_ENV`, ...) can
  never be set through the API. Writes reject command substitution and control characters.
- Compose content goes through the compose policy (below) before it is written or deployed.
- URLs fetched by the server (templates, webhooks, plugins) are checked against private and
  link-local ranges and redirects are not followed.
- Archives (backups, snapshots) are listed before extraction; absolute paths, `..` entries and
  symbolic links are refused.
- Background jobs started by a request are detached from the client socket, so a slow job can
  never hold a connection open or write into an HTTP response.

### Compose policy

What a compose file may ask of the host is judged on the file **as it will run**, not on its
text: Docker Compose resolves it (`docker compose config --format json` with the stack's `.env` and
the server's environment, every profile on, `include:` and `extends:` followed, `${VAR}` filled
in), and the rules in `.lib/compose-policy.jq` read the result. A value on the next line, flow style,
anchors and merge keys, the long volume syntax, a named volume that is a bind, a `${VAR}` the `.env`
sets to `/`, a path through `..` or a link: none of it changes the verdict. Where Docker Compose is
not there (a VM before Docker is installed) `.lib/compose-policy.py` reads the file itself (PyYAML
when present, else a small YAML reader of its own) and the same rules judge it; the answer says which
engine did (`policy.engine`). The stored secrets are not filled in (their values would land in the
findings): a `${SECRETS_X}` is judged as empty.

| Refused (root on the host in all but name) | Warned |
|---|---|
| `privileged`; `cap_add` ALL, SYS_ADMIN, SYS_MODULE, SYS_RAWIO, DAC_READ_SEARCH, SYS_BOOT | `network_mode: host`; `cap_add` NET_ADMIN, SYS_PTRACE, BPF, PERFMON |
| `pid`, `ipc`, `cgroup` or `userns_mode`: `host` | the Docker socket read-only (`:ro` does not stop API calls: the socket proxy template is the way) |
| `security_opt` seccomp, AppArmor or systempaths `unconfined` | a device of the usual kinds (`/dev/dri`, `/dev/net/tun`, USB serial sticks, `/dev/bus/usb`, sound, video, `/dev/kvm`, …: `devices.warn`) |
| a mount of `/`, `/etc` (a file under it read-only is fine), `/proc`, `/sys`, `/boot`, `/dev`, `/root`, `/home/*/.ssh` | `/sys/…` or `/var/lib/docker` read-only; `/home` writable; a folder that holds DCS, read-only |
| the Docker (containerd, podman) socket or `/run` writable; `/var/lib/docker` writable | `sysctls` outside `net.*`; device cgroup rules; `volumes_from` another container |
| DCS's own folder (its accounts, secrets key, scripts; `Stacks/<stack>/` is fine), or a folder that holds it, writable | a socket proxy with `POST=1` |
| any other device (a disk, `/dev/mem`), a device rule for every device | |
| `build:` context, `include:`, `extends: file`, `env_file:`, `configs`/`secrets` `file:` outside the stack's folder | |

Exceptions are named rules for an image (by prefix: `netdata/netdata` matches `netdata/netdata:stable`,
not `netdata/netdata-evil`) or a stack, optionally one service, each with its reason. DCS ships its
own in `.config/compose-policy.json` (Portainer, Watchtower and Sablier with the Docker socket,
Tailscale, WireGuard, Gluetun and Pi-hole with NET_ADMIN, Plex, Jellyfin, Emby and Home Assistant on
the host network, the monitoring agents with `/proc` and `/sys`, …); a server's own go in
`.data/compose-policy.local.json` through `GET`/`PUT /config/compose-policy` (admins). An allowed
refusal is still reported, as a warning with its reason; an allowed warning is listed as allowed. An
allowed image is trusted with its rules whatever its `command` says: allow by stack when in doubt. A
template's own `host_access` (and a deploy's `allow_privileged`) is allowed for that deploy.

Where it runs: an edit (`POST /stacks/{s}/compose`, the editors' checks `POST /stacks/{s}/compose/validate`
and `POST /compose/validate` with the findings and their lines), `POST /stacks/{s}/files` (the folder
is put back when the result is refused), a `.env` save and a container's environment change (refused
for what they add), a rollback, a snapshot restore, a template deploy (after its variables are filled
in), a template import or update (at its defaults), and the hub's push of a stack's files into a VM:
those refuse with 422 and the findings. A stack moved from a VM back to the hub is judged on the hub
before anything stops in the VM; a refusal fails the move at its Files step. A start, restart, update or recreate, and the setup wizard,
report what a file already on disk would be refused for (in the answer and the audit log) and go on:
a file an admin wrote by hand is the admin's. Verdicts are cached by the hash of the file, its `.env`,
the root `.env` and the policy files (`.data/compose-policy-cache.json`, the newest 300).
`tests/lint.sh` runs every template through the policy with its defaults.

The policy keeps the promise against mistakes and against content an admin did not read (a template
from a URL, a pasted file). It is not a sandbox against a hostile admin, who can edit the crontab.

### Plugins and hooks

Plugin hooks are user-supplied scripts. They run with a minimal environment (never the server's
`.env`), a 30-second timeout and bounded output, only when the plugin's manifest says
`"enabled": true`, and never through symbolic links. Installing, writing and testing hooks requires
`admin`.

### Web terminal

The terminal runs commands as the API service account, so it can only be unlocked with that
account's (or root's) Linux password, in addition to an admin API session. Commands run with a
60-second limit, are written to an audit log and pass through a denylist for obviously destructive
patterns. The denylist is a guard rail, not a boundary: an admin with terminal access is trusted.

## Operator checklist

- Run the API as an unprivileged user in the `docker` group (`.scripts/install-service.sh` sets
  this up with a hardened systemd unit).
- Keep `API_BIND=0.0.0.0` only on a trusted network; put Traefik (`API_BEHIND_TLS_PROXY=true`) or
  the API's own TLS (`API_TLS_ENABLED=true`) in front of it for anything reachable from elsewhere.
- Restrict `API_IP_WHITELIST` to your LAN or VPN ranges.
- Give day-to-day users the `user` role; create admins sparingly.
- Back up `.secrets/.master-key` separately from the encrypted secrets.
- `.env`, `.api-auth/` and `.secrets/` are ignored by git and created with mode `600`/`700`; keep
  them that way.
