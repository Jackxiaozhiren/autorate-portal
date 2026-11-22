# PostgreSQL and the container — 2026-11-22

Two gaps had been recorded as environment limitations rather than results: the migration chain had
only ever run on SQLite, and the image had never been built (`V1-B6 = not-run`, 2026-11-17). Both
were closed on this machine by starting the Docker daemon that was already installed. Every number
below is a command's own output, captured 16:49–17:05 GMT+8.

## Environment

- portal tip `8cd75d0` plus the working-tree changes for the Dockerfile and `tests/test_dockerfile.py`
- Docker Desktop `29.9.3`, daemon started for this check (it was installed, not running)
- `postgres:17` → `PostgreSQL 17.12 (Debian 17.12-1.pgdg13+1) on aarch64`, container `autorate-pg`,
  published on `127.0.0.1:55432`, throwaway password
- host `psycopg 3.3.8` (the `postgres` extra, locked in `uv.lock`; installing it does not change the
  lock file)

## Gate rows

| Row | What it asks | Reading | Verdict |
|---|---|---|---|
| P1 | the migration chain applies to a real PostgreSQL | `alembic upgrade head` → `alembic_version = 0005_artifact_wheel_kind`; 16 tables created | pass |
| P2 | 0005 changes the constraint instead of rebuilding the table | `pg_constraint` reads one CHECK: `kind = ANY (ARRAY['certificate','document','records','protocol','transcript','wheel'])`; the `artifact` table kept its rows across the ingest that followed | pass |
| P3 | a real bundle ingests | `state: indexed`, manifest packet `pkt-4e5b1b6a994777f0`, row `pkt-e553659eda3b532a`; 33 artefacts (`protocol 1, document 19, certificate 7, records 6`); 7 certificate summaries | pass |
| P4 | AC14 holds on PostgreSQL, not only on SQLite | same project, same bundle again → still **1** packet row, note `already ingested; one row, no duplicate artefacts`, 33 artefacts; a second project gets its own row (`pkt-a3204d33e65bbece`) with its own 33 | pass |
| P5 | the image builds | `docker build` 3m17s from scratch, then 57s after the definition fix; `autorate-portal:gate` `sha256:53b5487d5cbd…`, 293 MB | pass |
| P6 | a container with no environment refuses with the reason the comment gives | `REFUSING TO START: refusing to start: token salt: set AUTHORATE_TOKEN_SALT; session/share secret: set AUTHORATE_SECRET_KEY.` | pass |
| P7 | the two secrets are enough to serve | `healthz 200` after 4 s, process uid `10001`, `/data/portal.db` 180 224 bytes | pass |
| P8 | the same image talks to PostgreSQL | `healthz 200` after 4 s, `psycopg 3.3.9` inside the image, and the container reads the rows the host wrote: `packets: 4`, `artefacts: 132` | pass |

Both app containers report `(healthy)`, so the declared `HEALTHCHECK` is exercised rather than
merely declared.

## Two defects the run found

Neither was visible to any test that only reads files; both were found by building and running the
image.

**The image could not reach PostgreSQL at all.** `pip install .` installs no extras, so every
`postgresql://` URL raised `ModuleNotFoundError: No module named 'psycopg'` inside the container.
The definition now installs `".[postgres]"`.

**A container with no environment failed for the wrong reason.** No `AUTHORATE_DB_URL` was set, so
the default relative path `autorate-portal.db` resolved to `/app`, which uid 10001 cannot write:
`sqlite3.OperationalError: unable to open database file`. The comment promised a refusal about
credentials, and that is not what an operator would have seen. The image now defaults to
`sqlite:////data/portal.db`, so the declared volume is the state and the documented refusal is what
actually appears.

`tests/test_dockerfile.py` pins all four claims (the extra, the volume path, no credential in a
layer, unprivileged user and healthcheck). Full suite after the fix: **382 passed, 1 warning**.

## One reading worth writing down

`IngestResult.packet_id` is the manifest's packet identity and is the same in every project;
`IngestResult.row_id` is the row. `IngestResult.packet_id` is deliberately **not** the database key —
AC14 keys on `(project_id, manifest_sha256)`, so two projects holding the same bundle hold two rows
under one packet identity. Reading `packet_id` as a row id makes the AC14 check look wrong when it
is right.

## What this does not prove

- **Not a production database.** One node, no TLS, no backup/restore drill, no concurrent-writer
  load, no failover. P1–P4 say the schema and the ingest work on PostgreSQL; they say nothing about
  operating it.
- **Not a hardened image.** No vulnerability scan, no signature, no SBOM, and the base tag
  `python:3.13-slim` floats. P5 says it builds; it does not say it is fit to ship.
- **One architecture.** arm64 only, on this machine. CI's container replay runs on the runner's
  own architecture, which is not the same evidence.
- **Migrations are not safe to run concurrently.** The image applies `alembic upgrade head` at
  start, so two replicas starting together would race. That is untested, and it is the first thing
  to fix before any multi-replica deployment.
