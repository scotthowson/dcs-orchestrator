<sub>[← Troubleshooting](TROUBLESHOOTING.md) · [Docs index](README.md) · Next: [Proxmox and the fleet →](PROXMOX.md)</sub>

# Development

How the code is laid out, how to test it, and how to run the API while you work on it.

## Two repositories

| Repository | What it holds |
|---|---|
| [dcs-orchestrator](https://github.com/scotthowson/dcs-orchestrator) (this one) | The Bash framework, the API, the stacks, the templates, the plugins, the VM images and these docs |
| [dcs-orchestrator-ui](https://github.com/scotthowson/dcs-orchestrator-ui) | The dashboard: a React app built with Vite, published as the `ghcr.io/scotthowson/dcs-orchestrator-ui` image and as Android, Linux and Windows apps |

Everything here is Bash 4+, Docker Compose v2 and `jq`. There is no build step.

## Repository layout

| Path | Role |
|---|---|
| `setup.sh`, `start.sh`, `stop.sh`, `restart.sh`, `status.sh`, `compose.sh` | The entry points |
| `.config/settings.cfg` | The default of every setting |
| `.lib/` | Libraries the scripts source: logging, Docker helpers, `.env` files, secrets, plugins, setup checks; the API loads the CrowdSec page and the chat on demand |
| `.scripts/api-server.sh` | The REST API: the router `handle_request` and the `handle_*` handlers |
| `.scripts/api-dispatch.sh` | The front `socat` runs per connection: reads the request and hands it to a worker of the pool |
| `.scripts/api-docs.sh` | Generates `docs/API.md` and the `GET /` catalogue from the router |
| `.scripts/fleet-bootstrap.sh` | What the hub runs inside a new VM: Docker, the hub's code, the member setup, the join |
| `.scripts/*.sh` (others) | Tools with `--help`: install-service, stack-manager, health-check, maintenance… |
| `Stacks/<category>/` | The ten stacks, each a `docker-compose.yml` and a `.env` |
| `.templates/<name>/` | The templates: `docker-compose.yml`, `template.json`, optional `config/` |
| `.plugins/`, `.plugins-catalog/` | The bundled plugins and the catalogue ([plugin guide](../.plugins/README.md)) |
| `vm-images/` | The purpose-built VM images *(new in 4.0)* |
| `tests/` | `lint.sh`, `smoke.sh`, an opt-in CrowdSec replay test, and stand-ins for Proxmox and Cloudflare |
| `docs/` | These pages; `docs/API.md` is generated, `docs/tools/` holds the generators |

The API writes its state to `.api-auth/`, `.data/`, `.secrets/` and `logs/`; git ignores them.

## How the API works

- **A pool of workers.** `socat` listens and runs the small front (`.scripts/api-dispatch.sh`) for every
  connection; the front reads the request and hands it to a free worker, a copy of `api-server.sh` that
  has read the script once (`API_WORKERS`, automatic when empty: twice the cores, 4 to 8). A request runs
  in a subshell of the worker, so nothing it sets survives into the next; an event stream, or a request
  that finds no free worker, gets a process of its own. `API_WORKERS=0` (and an `ncat` host) is the old
  transport: one `api-server.sh --handle-request` per connection, the request on stdin and the answer on
  stdout, which is also how the smoke tests drive it. The listener is supervised, so SIGTERM stops it cleanly.
- **Roles in one place.** `_api_route_allowed METHOD PATH` decides who may call what. New routes that
  change something or expose a secret are admin-only there; handlers check again.
- **`.env` is data.** It is parsed as `KEY=value` lines and never sourced by the API. Writes go through
  the validators.
- **JSON with jq.** Build JSON and filters with `--arg` and `--argjson`, never by pasting user data into
  a filter. Update JSON files atomically with `_api_jq_update_file`.
- **Background work is detached** (`( … ) </dev/null >/dev/null 2>&1 &`), so it can never hold the
  client's connection open.

`CLAUDE.md` in the repository root has the full list of conventions.

## Helpers and where they live

One helper per job. Before writing a pipeline that reads `.env`, checks a container or takes a lock, look
here: the helper below is the one the rest of the code uses, with the same arguments and exit status.
Helpers the lazily loaded libraries (`crowdsec.sh`, `crowdsec-config.sh`, `chat.sh`) call live in
`api-server.sh` or in a library it sources at start (`envfile.sh`, `secrets.sh`).

| Job | The helper | Where | What it replaced |
|---|---|---|---|
| Answer a request | `_api_success BODY`, `_api_error CODE MESSAGE`, `_api_response CODE BODY` | `api-server.sh` | — |
| A string inside hand-built JSON | `_api_json_escape` (also strips ANSI and control characters) | `api-server.sh` | — |
| Update a JSON file | `_api_jq_update_file FILE [jq args] FILTER` (tmp + lock + mv) | `api-server.sh` | — |
| Read one `.env` key | `envfile_get FILE KEY` (first line, every quote character dropped) | `.lib/envfile.sh` | 18 inline `grep -m1 '^KEY=' … \| cut \| tr` reads |
| Load a whole `.env` as data | `_api_load_env_file FILE` (quotes, escapes, comments, reserved keys) | `api-server.sh` | — |
| A key over every stack's `.env`, then the root one | `_stack_envs_first KEY` | `api-server.sh` | the loops in `_find_traefik_domain`, the template deploy, the CrowdSec trusted LAN (×2) |
| Write a root `.env` key | `_api_env_write KEY VALUE` (bash quoting, line moved to the end) | `api-server.sh` | the copy inside `POST /config` |
| Write a stack `.env` key | `_envfile_set FILE KEY VALUE [bash\|compose]` (quoted, in place) | `api-server.sh` | — |
| Quote a value for `.env` | `envfile_quote VALUE [bash\|compose]` | `.lib/envfile.sh` | — |
| Now, as ISO 8601 UTC | `_api_now_iso`; epoch seconds are plain `date +%s` | `api-server.sh` | 52 inline `date -u '+%Y-%m-%dT%H:%M:%SZ'`, the wrapper `_api_now_epoch` |
| Is version A at or after B | `_version_ge A B` (`sort -V`) | `api-server.sh` | 2 inline `sort -V \| tail` comparisons (kernel, Docker engine), the unused `_cs_version_ge` |
| Is a container running | `_container_running NAME` | `api-server.sh` | 12 inline `docker inspect -f '{{.State.Running}}'` tests |
| A container's label | `_container_label NAME LABEL` | `api-server.sh` | 13 inline compose-label inspects |
| Run cscli in CrowdSec | `_cs_run OUTVAR ARGS…` (stdout into OUTVAR, stderr into `CS_ERR`, 25 s); `_cs_pipe OUTVAR TEXT ARGS…` (the same with TEXT on stdin, `docker exec -i`, 60 s) | `.lib/crowdsec.sh` | — |
| The Traefik routes folder | `_find_traefik_routes_dir` (any App-Data, then the feed's `.data/routes`); `_traefik_stack_routes_dir` (only the stack whose compose file runs Traefik) | `api-server.sh` | three copies of the second lookup in the template deploy and removal |
| Write a file CrowdSec's config folder may not let us write | `_crowdsec_conf_put DIR REL CONTENT` (direct, else `docker cp`) | `api-server.sh` | — |
| Lock `tokens.json` / `users.json` | `_api_with_auth_lock tokens\|users CMD…` | `api-server.sh` | `_api_with_tokens_lock`, `_api_with_users_lock`, the inline lock of `_api_store_token` |
| Is a job's lock held | `_lock_busy LOCKFILE` | `api-server.sh` | 3 inline `flock -n` probes |
| Start a detached job of the API script | `_api_job_launch LOCKFILE LOG ARGS…` | `api-server.sh` | the two copies in `_self_update_launch`, `_image_update_launch` |
| Unattended-update history | `_update_history_add dcs\|images RESULT MESSAGE [FROM TO]` | `api-server.sh` | `_self_update_history_add`, `_image_update_history_add` |
| A sliding-window rate limit | `_api_rate_window FILE LIMIT SECONDS` | `api-server.sh` | the terminal's own copy (`_terminal_rate_limited` is now a call) |
| Audit | `_api_audit_log IP EVENT USER DETAIL` (auth log, mirrored), `_audit_log ACTION DETAIL` (the JSON log behind `GET /audit` and webhooks) | `api-server.sh` | — |
| Secrets | `secrets_get`, `secrets_env_exports`, `compose_with_secrets` | `.lib/secrets.sh` | the aliases `_decrypt_secret`, `_secrets_env_exports`, `_compose_with_secrets` |
| A compose file backup before a template changes it | `_compose_backup DIR TIMESTAMP` (`.bak.TIMESTAMP`, newest 5 kept) | `api-server.sh` | the copies in the template deploy and removal |
| Parse a `.env` for the editor | `_env_file_vars_json FILE` | `api-server.sh` | the copies in `GET /env`, `GET /stacks/{stack}/env` |
| Terminal title, the traps' exit | `_set_terminal_title`, `_graceful_exit` | `.lib/docker-utils.sh` | the copies in `start.sh` and `stop.sh` |

Kept apart on purpose:

- **`_envfile_set` and `_stack_env_set`.** `_envfile_set` quotes the value and also replaces `export KEY=`
  and `KEY =` lines; `_stack_env_set` writes the value as given (Traefik add-on switches) and matches
  `KEY=` only.
- **`_pve_norm_url` (API) and `_pve_clean_url` (`.lib/setup-checks.sh`).** The API turns `http` into `https`
  only on port 8006; setup turns it always and retries plain `http` itself. Different processes, different rule.
- **The `.bak` names.** `.env.bak` (one, overwritten), `docker-compose.yml.bak.TIMESTAMP` (template changes,
  newest 5), `configuration.yml.bak-TIME` (Authelia), `.bak-repair` (`envfile_repair`), CrowdSec's
  `*.TIME.bak` inside the container: the restore, the backup excludes and the cleanups know these names.
- **The audit files.** `auth-audit.log`, `.data/audit.jsonl`, `terminal-audit.log`, `terminal-auth-audit.log`
  and `cf-dns-audit.log` have their own formats and readers.
- **Writing Authelia's `configuration.yml`** rewrites the file in place (`cat >`, directly or through
  `docker exec -i Authelia`), after a dated backup; `_crowdsec_conf_put` replaces a file (`mv`, or `docker cp`).
- **Timeouts around `docker exec`** differ per call (8 to 60 s) on purpose: a `cscli` import is not a `test -e`.
- **Hand-built 4xx bodies with a `reason`** (CrowdSec, chat) answer through `_api_response`, which does not count
  them in the error statistics the way `_api_error` does; merging them would change `GET /stats`.
- **The scenario labels** live once, in `_CS_LABEL_TABLE` (`.lib/crowdsec.sh`). The Discord template's
  `if hasPrefix …` chain is generated from it (`_cs_notify_go_template`); the shipped
  `.templates/crowdsec/files/notifications-discord.yaml` is that output, kept so a template deploy works
  without the CrowdSec page, and `tests/smoke.sh` (notify/golden) fails when the two differ.
- **The standalone tools** (`health-check.sh`, `logs-viewer.sh`, `maintenance.sh`, …) keep their small `_xx_repeat`
  and color helpers: each runs from a bare checkout without sourcing a library.
- **`_jsonl_escape`** (`.lib/logger.sh`) serves `start.sh`'s structured log, outside the API.
- **The ntfy pushes** of `.scripts/run.sh`, `.scripts/stop.sh` and `ntfy-status.sh` differ in title, priority, tags and
  target (`NTFY_URL` or `_ntfy_target`), and in what a failed `curl` returns (some end in `|| true`, some do not).
- **`_api_update_user_hash_locked` and `_api_totp_update_user_locked`** each change their own fields of one account under
  the same lock; one generic writer would add a `jq` run to every sign-in and hide which fields a path may touch.
- **A stack's App-Data folder** is worked out two ways: `_stack_appdata_dir` (the stack's drive, else `APP_DATA_DIR`
  made absolute below the stack's folder, trailing `/` dropped) and an inline rule in the Traefik and Authelia code paths
  (only a leading `./` is resolved). They agree for the shipped `./App-Data` and for absolute paths; they differ for a
  relative `APP_DATA_DIR` without `./` and for a trailing `/`, so making them one is a behaviour change left for a decision.

## Tests

```bash
tests/lint.sh                  # bash -n, shellcheck, compose validation, API reference freshness
tests/smoke.sh                 # the API's request handler in a temporary install
tests/crowdsec-media-apps.sh   # opt-in: CROWDSEC_MEDIA_APPS replayed through the real CrowdSec (needs Docker, the image, the network)
.scripts/api-docs.sh --check   # docs/API.md and the GET / catalogue are current
docs/tools/gen-templates.sh --check   # docs/TEMPLATES.md is current
./setup.sh --dry-run           # setup, without changing anything
```

- **`tests/lint.sh`** runs `bash -n` and ShellCheck (`-S warning`) on every script, validates the
  compose file of every stack and template with its own defaults, checks the JSON files and the API
  reference. ShellCheck 0.10 or newer is best: the linter then skips the extended analysis that needs a
  lot of memory on the API script. Compose validation is skipped without Docker.
- **`tests/smoke.sh`** drives the request handler over stdin, the way `socat` does, in an isolated copy
  in a temporary folder: no listener, no network. It runs over 1,100 checks, including a whole VM build
  against the Proxmox stand-in (`tests/mock-proxmox.py`) and DNS against the Cloudflare one
  (`tests/mock-cloudflare.py`). The checks that need Docker are skipped without it.

CI (`.github/workflows/ci.yml`) runs the linter, the smoke suite and the setup dry run on every push to
`main` and `release/**` and on every pull request. Keep both suites green.

## Run the API while you work

**One request, no listener.** The quickest way to try a handler:

```bash
cp .env.example .env
printf 'GET /ping HTTP/1.1\r\nHost: dev\r\n\r\n' | .scripts/api-server.sh --handle-request
```

**A listener on loopback.** Use a clone of your own (never the install that runs your stacks) and
start it with its full path, which `--stop` uses to recognise its own server:

```bash
"$PWD/.scripts/api-server.sh" --bind 127.0.0.1 --port 9877
```

```bash
curl -s http://127.0.0.1:9877/ping      # {"ok": true, "version": …}
curl -s http://127.0.0.1:9877/status    # 401: create the first admin with POST /auth/setup
.scripts/api-server.sh --stop
```

On a loopback address you may set `API_AUTH_ENABLED=false` in the clone's `.env` to skip accounts
while testing; on any other address the API refuses to run without them.

**A stand-in Proxmox.** `tests/mock-proxmox.py` answers like a Proxmox node with a few guests:

```bash
python3 tests/mock-proxmox.py 18006 'dcs@pve!dev' 00000000-0000-0000-0000-000000000000
```

Then link it with `PROXMOX_URL=http://127.0.0.1:18006`, `PROXMOX_TOKEN_ID=dcs@pve!dev` and that secret.

**The dashboard from source.** In a clone of the UI repository:

```bash
npm ci
npx vite --port 3014 --strictPort
```

Open `http://localhost:3014`. The dev server forwards `/api` to `http://127.0.0.1:9876`, the default API
port; for an API elsewhere, type its address into the server field of the sign-in or setup screen.

## Adding an API route

1. Write the handler with a comment on the line above it: `# METHOD /path — what it does`. Use the
   [shared helpers](#helpers-and-where-they-live) rather than a new copy of their pipelines.
2. Add the route to the router and validate every path parameter with the `_api_validate_*` helpers.
3. Decide who may call it in `_api_route_allowed`.
4. Run `.scripts/api-docs.sh` to regenerate `docs/API.md` and the `GET /` catalogue.
5. Add smoke checks and run both suites.

## Adding a template

1. Make `.templates/<name>/` with a `docker-compose.yml` and a `template.json`
   ([field reference](TEMPLATES.md#templatejson-reference)), and a `config/` folder if the app needs files
   before its first start.
2. Use `${APP_DATA_DIR:-./App-Data}/<Name>/…` for bind mounts, `${PUID}`, `${PGID}` and `${TZ}`, and a
   `healthcheck` where the image can run one.
3. Deploy it for real and watch it become healthy. Write in the description what to do after the first start.
4. Run `tests/lint.sh` and `docs/tools/gen-templates.sh`.

## VM images

*New in 4.0.* `vm-images/` builds the node and hub images without root: the root file system is built
in Docker, then assembled into a disk that boots with BIOS and UEFI.

```bash
vm-images/build.sh debian-13 node          # out/dcs-node-debian-13.qcow2
vm-images/build.sh debian-13 hub --test    # build, then boot it in QEMU and check it
```

Options: `--ref GIT_REF` (the DCS code a hub image carries, default `HEAD`), `--size MB` (disk size,
default 4096), `--firmware bios|uefi|both`. `--test` needs `qemu-system-x86_64`, `qemu-img`, `ssh` and
`genisoimage`, and OVMF for UEFI. `vm-images/tests/measure.sh USER@HOST` prints the same figures for a VM
on a real Proxmox node. The images are described in [VM images](VM-IMAGES.md).

To look around in a hub without Proxmox, boot the image in QEMU and keep it running; the script prints
the local ports of the dashboard, the API and ssh:

```bash
vm-images/tests/boot-test.sh vm-images/out/dcs-hub-debian-13.qcow2 --role hub --hold
```

## Releases

- `VERSION` holds the release version; `.config/settings.cfg` and the API read it.
- The API's protocol version is `API_VERSION` in `.scripts/api-server.sh`.
- `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); new work goes under
  *Unreleased*.
- The Updates page's `stable` channel follows the `vX.Y.Z` tags.
