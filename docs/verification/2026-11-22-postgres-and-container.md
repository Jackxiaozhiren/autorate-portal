# PostgreSQL and the container — 2026-11-22

Two gaps had been recorded as environment limitations rather than results: the migration chain had
only ever run on SQLite, and the image had never been built (`V1-B6 = not-run`, 2026-11-17). Both
were closed on this machine by starting the Docker daemon that was already installed. Every number
below is a command's own output, captured 16:49–17:05 GMT+8, except the two sections added the
same evening (18:07–18:49), which say so where they start.

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
| P1 | the migration chain applies to a real PostgreSQL | `alembic upgrade head` → `alembic_version = 0005_artifact_wheel_kind`; 15 tables (the model's count; this row said 16 until it was recounted on 2026-11-22 against `SECTION_4_3` + `audit_row` + `monitor_schedule` + `alembic_version`) | pass |
| P2 | 0005 changes the constraint instead of rebuilding the table | `pg_constraint` reads one CHECK: `kind = ANY (ARRAY['certificate','document','records','protocol','transcript','wheel'])`; the `artifact` table kept its rows across the ingest that followed | pass |
| P3 | a real bundle ingests | `state: indexed`, manifest packet `pkt-4e5b1b6a994777f0`, row `pkt-e553659eda3b532a`; 33 artefacts (`protocol 1, document 19, certificate 7, records 6`); 7 certificate summaries | pass |
| P4 | AC14 holds on PostgreSQL, not only on SQLite | same project, same bundle again → still **1** packet row, note `already ingested; one row, no duplicate artefacts`, 33 artefacts; a second project gets its own row (`pkt-a3204d33e65bbece`) with its own 33 | pass |
| P5 | the image builds | `docker build` 3m17s from scratch, then 57s after the definition fix; `autorate-portal:gate` `sha256:53b5487d5cbd…`, 293 MB | pass |
| P6 | a container with no environment refuses with the reason the comment gives | `REFUSING TO START: refusing to start: token salt: set AUTHORATE_TOKEN_SALT; session/share secret: set AUTHORATE_SECRET_KEY.` | pass |
| P7 | the two secrets are enough to serve | `healthz 200` after 4 s, process uid `10001`, `/data/portal.db` 180 224 bytes | pass |
| P8 | the same image talks to PostgreSQL | `healthz 200` after 4 s, `psycopg 3.3.9` inside the image, and the container reads the rows the host wrote: `packets: 4`, `artefacts: 132` | pass |

Both app containers report `(healthy)`, so the declared `HEALTHCHECK` is exercised rather than
merely declared.

## Concurrent starts (added the same day, 18:07-18:40)

P5-P8 built the image but left one risk named rather than tested: the boot step ran
`alembic upgrade head` with no lock, so two replicas starting together would send the same DDL.
The fix is `autorate-portal migrate`, which holds a schema lock for the length of the upgrade
(a PostgreSQL advisory lock keyed on `current_database()`, or a `flock` on
`<database>.migrate.lock` for SQLite). The readings below first reproduce the race, then show it
closed on both databases and on the image itself.

| Row | What it asks | Reading | Verdict |
|---|---|---|---|
| P9 | the race is real on PostgreSQL | four `alembic upgrade head` processes on one empty database: **1 exited 0, 3 exited 1** — `psycopg.errors.UniqueViolation: duplicate key value violates unique constraint "pg_type_typname_nsp_index"`, `DETAIL: Key (typname, typnamespace)=(alembic_version, 2200) already exists` | reproduced |
| P10 | the same four, through the lock | four `autorate-portal migrate` processes on one empty database: **4 × exit 0**, each printing `schema at 0005_artifact_wheel_kind`; `alembic_version` holds one row, 15 tables | pass |
| P11 | the race is real on SQLite too, and closed there | four threads on one new file: without the lock **4/4 failed** (`table alembic_version already exists`, `KeyError: 'script'`); with it **4/4** returned the head and `certificate_summary` has 0 rows, not two copies of the table | pass |
| P12 | three image replicas may start together | three containers on one empty database: `healthz 200` for all three after 4 s, all `(healthy)`, one revision | pass |
| P13 | a migration job, then replicas that skip it | one-shot `docker run … autorate-portal migrate` → exit 0; a replica with `AUTHORATE_MIGRATE_ON_START=0` logs `migrate: AUTHORATE_MIGRATE_ON_START is off; the schema is another job's step`, `healthz 200`, and `POST /api/v1/session` answers **401** — it read `api_token`, so the schema it did not create is there | pass |
| P14 | a held lock refuses rather than waiting forever | a psql session holding the advisory lock + `--timeout 2` → `REFUSING TO MIGRATE: another process holds the schema lock on database 'autorate_held'; waited 2s (AUTHORATE_MIGRATE_LOCK_TIMEOUT)`, exit **4**, and **0** tables created — a refusal leaves no half schema | pass |
| P15 | skipping the step without running the job is caught by someone | `AUTHORATE_MIGRATE_ON_START=0` on an **unmigrated** database: `healthz 200`, `POST /api/v1/session` → **500** | negative control: nothing catches it |

P15 is the reason P13 is worded as a contract and not a convenience: `/healthz` returns a
constant and never touches the database, so a replica that skipped the migration reports healthy
until the first real request. The job has to be sequenced **before** the replicas; the image does
not detect the reverse order.

## Readiness, so the orchestrator catches it (added 18:42-18:49)

P15 named a gap and left it open. `/readyz` closes it: one connection, `SELECT 1`, and the
revision in `alembic_version` compared against the head this build's chain ends at. `/healthz`
stays a constant and stays the container's `HEALTHCHECK`, because a liveness probe that reads the
database turns its outage into a restart loop. Every row below is the same rebuilt image
(`sha256:f3543b69…`) against `postgres:17`, driven by `curl`.

| Row | What it asks | Reading | Verdict |
|---|---|---|---|
| P16 | a replica that migrated at boot is ready | `/readyz` → 200 `{"status":"ready","schema":"0005_artifact_wheel_kind"}`; `/healthz` 200 | pass |
| P17 | **P15's case**: skipping the step with no job never becomes ready | `AUTHORATE_MIGRATE_ON_START=0` on an empty database: `/healthz` **200**, `/readyz` **503** `{"status":"not-ready","reason":"schema-missing"}` | pass |
| P18 | the job path becomes ready | one-shot job, then a skipping replica: `/readyz` 200 with the head | pass |
| P19 | a live replica notices the schema going backwards, and forwards | `alembic downgrade 0004_packet_tombstone` → 503 `{"reason":"schema-behind","applied":"0004_packet_tombstone","expected":"0005_artifact_wheel_kind"}`; `upgrade head` → 200 again, without a restart | pass |
| P20 | a database outage is not a reason to restart | `docker stop autorate-pg` → `/healthz` **200**, `/readyz` **503** `{"reason":"database-unreachable"}`, container still `(healthy)`; `docker start` → `ready` again | pass |

The refusal body carries a fixed code and no driver text: `tests/test_readiness.py` asserts a
`postgresql://portal:hunter2@…` URL produces an answer containing neither `hunter2` nor
`postgresql`. The probe is unauthenticated, and a driver's message quotes the URL.

`schema-unverified` exists for a build that cannot locate its chain. It should not arise for
anything shipped: `pyproject.toml` now force-includes `migrations/` into the wheel (6 files,
verified by listing the built wheel), and a clean venv with only the wheel installed runs
`autorate-portal migrate` from a directory with no `alembic.ini` and reports
`packaged migrations: …/site-packages/autorate_portal/migrations`, `head: 0005_artifact_wheel_kind`.

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
- **Concurrent starts are serialised, not orchestrated.** P9-P20 show the lock and the probes do
  their job on one host and in containers started by hand. They do not exercise an orchestrator:
  no rolling update with live traffic, no pod killed mid-migration, and no real readiness gate —
  the probes were driven by `curl`, not by a scheduler that acts on the answer. No manifest for any
  orchestrator ships with this repository, so the probe contract is documented and testable rather
  than configured.
- **A killed lock holder was never killed.** The lock is released when the holding connection
  dies, so a replica killed mid-migration should not wedge the next one. That is a property of
  advisory locks and of `flock`, not something measured here.
- **The timeout is a default, not a measurement.** 120 s was never reached in any run (the slowest
  upgrade took 4 s end to end including container start). A deployment whose largest migration
  takes longer than the default will refuse and restart; `AUTHORATE_MIGRATE_LOCK_TIMEOUT` is the
  knob, and its interaction with a short startup deadline was not tested.
