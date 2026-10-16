# Stacks

One folder per stack: `docker-compose.yml`, `.env` and the stack's `App-Data/`. Everything here is yours: git
tracks none of it, so no update, `git pull` or `git reset --hard` can change a stack file.

A fresh checkout gets the ten default stacks once, from `.config/stacks-seed/` (each file there has a `|` before
every line, which the copy takes off), the first time `./setup.sh` or the
API starts. A stack you delete stays deleted. Every DCS update also copies each stack's `docker-compose.yml` and
`.env` to `.data/update-backups/<stamp>/Stacks/` (with a `MANIFEST` of their SHA-256 sums) and puts back any
file the update changed.
