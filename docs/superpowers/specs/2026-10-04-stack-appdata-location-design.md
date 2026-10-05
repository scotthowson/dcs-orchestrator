# A stack's App-Data on another drive — design

Date: 2026-10-04 · Status: approved in conversation, awaiting review of this written spec

## Goal

When a stack is created on the hub, its App-Data folder can be placed somewhere other than `Stacks/<stack>/App-Data` —
typically on a bigger or faster drive (`/mnt/plex-2/appdata/<stack>`). Everything DCS does with a stack's App-Data keeps
working for that stack, and **nothing changes for any stack that does not use it**.

## Decisions (from the conversation)

- Reason: a bigger or faster drive for data-heavy stacks.
- Scope: chosen **when a stack is created**. Moving an existing stack's App-Data is a later release.
- Approach A: a per-stack setting that every part of DCS reads (not a symlink, not only the existing global root).
- Hard requirement: stacks without the setting behave exactly as today; every existing test passes unchanged.
- The stack card shows where each stack's App-Data is.

## 1. The setting and the lookup

- The setting is `APP_DATA_DIR=<absolute path>` in the stack's own `Stacks/<stack>/.env`, written only for stacks that
  chose a location. Templates already write `${APP_DATA_DIR:-./App-Data}/<App>/…`, so Compose needs no template change.
- One function, `_stack_appdata_dir STACK`, answers "where is this stack's App-Data": the stack's `.env` value when it
  is set and absolute; otherwise today's rule unchanged (the global `APP_DATA_DIR` when absolute, else
  `Stacks/<stack>/<relative path>`, normally `Stacks/<stack>/App-Data`). `_stack_appdata_root` (Nuke & reinstall) and
  every place listed in section 3 call it instead of computing the path themselves.
- For a stack without the setting, `_stack_appdata_dir` returns byte-for-byte what each call site computes today; a
  smoke check asserts this for the default (`./App-Data`) and the global-absolute layouts.

## 2. Compose always sees the stack's value

Docker Compose ranks an exported variable above `--env-file`. The API runs with the root `APP_DATA_DIR` exported, so a
stack's own value would be ignored there (at boot `.scripts/run.sh` re-reads the root and the stack `.env` before
Compose, so the stack value already wins on that path).

- `compose_with_secrets` (`.lib/secrets.sh`, used by the API, `compose.sh`, `run.sh`, `stack-manager.sh`, the
  scheduler and rollback) exports, inside its subshell, `APP_DATA_DIR` = the stack `.env` value when the stack sets
  one. When the stack sets none, the environment is left exactly as it is today.
- The API's direct `$DOCKER_COMPOSE_CMD` calls (46) are audited. Every call that creates or recreates containers, or
  reads the resolved configuration (`config`, used by the move facts and the bind-mount listing), uses the same
  per-stack export. Calls that only list, log or stop containers by project name are unaffected and stay as they are.
- `.scripts/stack-manager.sh` and `.scripts/update_all_stacks.sh` fall back to a raw compose call when the secrets
  library is missing; that fallback gets the same export.

## 3. Everything that follows the stack's App-Data

All of these use `_stack_appdata_dir` (or the per-stack compose export):

- **Backups** (`_backup_build`, `_backup_restore_run`): a stack whose App-Data is outside its folder gets one more part,
  `./.dcs-backup/appdata/<stack>.tar`, recorded in `manifest.json` with its absolute path (`appdata_path`). A restore
  writes it back to that path; when the path's drive is not there (no marker, section 4) the restore of that part is
  refused with a clear message and the rest of the restore proceeds. A one-stack backup and restore include it.
  `POST /backups/verify` checks the part like any other.
- **Moving a stack into a VM** (`_fleet_stack_data_dirs`, `_fleet_move_data`, move-check sizes): the external folder is
  copied into the VM's `Stacks/<stack>/App-Data`; the VM's `.env` gets no `APP_DATA_DIR` line (the VM uses its default).
  The original on the drive is left untouched, as the hub's copy is today.
- **Nuke & reinstall**: its roots come from `_stack_appdata_root`, so the trash folder is `<external path>/.trash`, on
  the same drive.
- **Template deploy**: the `config_path` first-start files, the Authelia files, the port and path checks and the
  SELinux `:z` labelling (`_selinux_label_volumes`) use the stack's App-Data.
- **Template undeploy / import**, **the file editor and App-Data browsing**, **App-Data sizes** (`/system` info,
  Disk Analysis, stack sizes), **Traefik / Authelia / CrowdSec config lookups** (`_traefik_stack_appdata` and the
  config finders): same lookup.
- **Deleting a stack** never deletes the external folder. The confirmation says so and names the path.

## 4. The drive is not mounted

At boot Docker restarts containers by itself, before DCS; with the drive missing, Docker creates an empty folder in
its place and the app starts "fresh" on the system disk.

- At creation DCS writes a marker file, `<path>/.dcs-appdata`, holding `{"stack": "<name>", "created": "<time>"}`.
- Before DCS starts, restarts, deploys into or updates a stack with an external App-Data (API handlers, `run.sh` at
  boot, the scheduler's updates), it checks the marker. Missing or naming another stack: the stack is not started,
  containers Docker already started for it are stopped, and a notification says
  "<stack> was not started: its App-Data <path> is not there — is the drive mounted?". Other stacks start normally.
- Nothing on the drive is ever touched in that case; what an app wrote meanwhile lands on the system disk below the
  mount point and is hidden again once the drive mounts.
- `GET /stacks` and the stack detail report `app_data: {path, external, ok, free_bytes}` (`ok` = marker present).

## 5. Creating a stack

- `POST /stacks` takes an optional `app_data_dir` and `app_data_adopt` (boolean). Without `app_data_dir` it behaves
  exactly as today.
- Checks, all before anything is created (400 with a reason on failure):
  - absolute, normalised (no `..`, no trailing slash), at most 4096 characters, no control characters;
  - not a system path: `/` itself, and `/bin`, `/boot`, `/dev`, `/etc`, `/lib*`, `/proc`, `/root`, `/run`, `/sbin`,
    `/sys`, `/usr`, `/var` and everything below them (drives live under `/mnt`, `/media`, `/srv`, `/opt` or `/home`);
  - not inside the DCS folder (except the stack's own folder, which is the default anyway), not inside another
    stack's App-Data, and not containing another stack's App-Data;
  - its parent folder exists (the drive is mounted), or the nearest folder that exists is on a mounted drive (not the
    system disk); DCS creates the missing folders itself;
  - writable by DCS, or creatable through `sudo -n` when available; it is owned by `PUID:PGID` afterwards;
  - an existing, non-empty folder is accepted only with `app_data_adopt: true` (the UI asks "use the existing data?").
- On success: the folder, the marker, and the `APP_DATA_DIR=<path>` line in the new stack's `.env` (with a comment).
- The drive list comes from the existing `GET /disks` (mount point, filesystem, size, free bytes); the dashboard
  suggests `<mount>/.dcs/App-Data/<stack>` (Scott's choice during the build; DCS makes the missing middle folders when the
  nearest existing folder is on a mounted drive, never on the system disk). (Amended during planning: a new `GET /storage/appdata-targets` would have
  returned the same data.)

## 6. Dashboard

- **Create stack dialog** (`CreateStackOverlay.tsx`): an *App-Data location* choice — *In the stack's folder*
  (default, today's behaviour) · *On a drive* (the list from `GET /disks` with free space; the
  suggested path is editable) · *Custom path*. Errors from the API are shown inline; a non-empty folder asks before
  adopting it.
- **Stack card and stack page**: an *App-Data* label on every stack: `Stacks/<stack>/App-Data` for the default, the full
  path with a drive icon and its free space for an external one, and a warning ("drive not mounted") when `ok` is false.
- **Delete stack**: the confirmation names an external App-Data path and says it is kept.
- Any new Tailwind colour classes are added to `themeClasses.ts` (`node scripts/theme-classes.mjs`).

## 7. Compatibility

- No migration: existing stacks have no `APP_DATA_DIR` line in their `.env` and keep today's behaviour everywhere.
- A stack `.env` that already sets a **relative** `APP_DATA_DIR` keeps today's meaning (relative to the stack folder).
- The global `APP_DATA_DIR` (root `.env`) keeps its meaning; a stack's own absolute value takes precedence for that
  stack only.
- Fleet members (VMs) are unaffected; a moved stack uses the VM's default.

## 8. Testing

- All existing suites unchanged and green: `tests/lint.sh`, shellcheck 0.9 (CI's), `tests/smoke.sh` (with mawk as
  `awk`, and the root case as CI's Debian job runs it), `tests/fleet-files.sh`, `tests/api-workers.sh`,
  `vm-images/tests/*`, `docs/tools/check-links.py`, `docs/tools/gen-templates.sh --check`, `./setup.sh --dry-run`.
- New smoke checks:
  - `_stack_appdata_dir`: default, global-absolute, stack override, relative stack value — and identical results to
    the old computations for stacks without the setting;
  - `compose_with_secrets` and the audited direct calls hand Compose the stack's value (checked with
    `docker compose config` on a fixture stack), and leave the environment untouched without it;
  - `POST /stacks` checks (each refusal), adopt, folder + marker + `.env` line, ownership;
  - backup and restore of an external App-Data part, the refused restore without the marker, verify;
  - the move copy into the VM layout (fleet-files);
  - the marker guard: refused start, notification, other stacks unaffected;
  - `GET /stacks` `app_data` fields.
- End to end on a throwaway copy of DCS on the desktop (port 9877), with a stack whose App-Data is on another disk
  (`/mnt/linux_drive/...`): create it, deploy a template, start, inspect the container's mounts, back up, restore,
  Nuke & reinstall, hide the marker to trigger the guard, delete the stack (folder kept).
- Dashboard: typecheck, `check:themes`, `build:renderer`, and a visual check of the dialog and the stack card.
- Release only after all of it is green locally and in CI.
