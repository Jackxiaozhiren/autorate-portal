# The walkthrough pack — 2026-11-23

T4 asks for two readers who are not the author. That is the one input this machine cannot supply, so
the gate stays open. What can be finished is the step before it: `docs/verification/v2-reader-gate-runbook.md`
could not be followed from a clean machine, because step 1 started from a database somebody had
already seeded by hand. `tools/walkthrough.py` is that missing step, plus a preflight that refuses to
let a facilitator invite a reader into a room that does not answer the way the runbook says it will.

Every number below is a command's own output on this machine, 16:26–16:52 GMT+8.

## What the tool is

| Command | What it does |
|---|---|
| `walkthrough.py packet --out <tar>` | builds the M4 demo packet **through `tests/conftest.py`**, not a copy of it |
| `walkthrough.py up` | builds the packet, migrates a fresh SQLite database, ingests, issues one token per reader, prints the serve command, the LAN address and two cards |
| `walkthrough.py seed` | the same seeding without the printout (the packet is reused if present) |
| `walkthrough.py check --base <url>` | signs in as each reader over HTTP and asserts the ten readings the runbook promises |

Two decisions are worth naming, because both were wrong in the first draft:

- **The packet is built by the fixtures.** A hand-copied builder would be a second source of truth:
  the suite would stay green while the file the facilitator hands out drifted from the file the suite
  asserts against. `test_the_pack_is_bit_for_bit_the_packet_the_suite_asserts_against` compares bytes
  with the `m4_built` fixture and would fail on any drift.
- **The schema comes from the migration chain.** The first draft called `db.create_all`, which builds
  every table and no `alembic_version` row. The database worked and `/readyz` answered
  `503 {"status":"not-ready","reason":"schema-missing"}` — the one probe built to be trusted, telling
  the facilitator the walkthrough was broken. Measured before the fix, green after it:

```
$ curl -s localhost:8111/readyz
{"status":"not-ready","reason":"schema-missing"}          # create_all
{"status":"ready","schema":"0005_artifact_wheel_kind"}    # migrate.upgrade_to_head
```

## Readings

```
$ .venv/bin/python tools/walkthrough.py up --root /tmp/t4/walk --reset
database : /tmp/t4/walk/portal.db
store    : /tmp/t4/walk/store
packet   : /tmp/t4/walk/demo.packet.tar (7 certificates)

readers open: http://172.20.10.5:8111/
  P1 (compliance, ada@example.test): <token>
  P2 (viewer, lin@example.test): <token>
```

The packet is `sha256 5a17d2486df41841758cbcb627df89489530f93061a74c3368fc9d66d6131f8e`, 34 tar
entries, 33 artefacts, 7 certificate summaries — every one of them `feasible = 0`, which is why all
three questions answer `cannot_be_bounded`. Building it twice on the same machine produces the same
hash, so a lost tarball can be re-issued rather than reconstructed.

`check` against the running service, as both readers:

```
ok   P1 identity       want ada@example.test/compliance/prj-laya got ada@example.test/compliance/prj-laya
ok   P1 certificates   want 7                                  got 7
ok   P1 Q1             want 200 cannot_be_bounded              got 200 cannot_be_bounded
ok   P1 Q2             want 200 cannot_be_bounded              got 200 cannot_be_bounded
ok   P1 Q3             want 422                                got 422 a claim needs share, field, unit and population; missing: fi
ok   P2 identity       ... (the same five, for u-lin)
exit 0
```

## The four worlds `check` was made to fail in

A preflight that can only print `ok` is worse than none: it turns "nobody measured" into "we verified
it". Each of these was run against a real server; the failing line is quoted.

| World | What the line says |
|---|---|
| migrated, never ingested | `FAIL P1 certificates  want 7  got 0` — and **only** that line; Q1–Q3 stay `ok` |
| token signed with another salt or mistyped | `FAIL P1 sign-in  want 200  got 401` |
| `tokens.json` missing a key | `FAIL P2 token  want present  got missing` |
| nothing listening | `nothing answered at http://127.0.0.1:8199 ([Errno 61] Connection refused); start the service first, or pass --base` |

The first row is the reason `check` counts certificates at all. `cannot_be_bounded` is the correct
answer both to "this pack never measured the field" and to "this project has no evidence", so the
three answers cannot tell an empty project from a measured one. Only the row count can. That is now
`test_certificates_are_the_only_line_that_notices_an_empty_project`, and it asserts the failing set
is exactly `["P1 certificates", "P2 certificates"]`.

## Mutations, so the new tests are not decoration

| Mutation | Result |
|---|---|
| `migrate.upgrade_to_head(...)` → `db.create_all(engine)` | `test_the_seeded_database_answers_ready` fails |
| `CERTIFICATES = 7` → `8` | `test_check_passes_against_the_world_up_built` fails on the count |
| drop `len(rows) == CERTIFICATES`, keep the request | the empty-project test fails |

Suite: **438 passed, 12 skipped in 99.24 s** (428 before this slice; the ten new ones are in
`tests/test_walkthrough.py`). Lint under the CI gate
(`ruff --select=E9,F63,F7,F82,F401,F811 --line-length=120`) is clean.

## The runbook's appendix was executed, not written

Step 1 now calls the tool. The manual path survives as an appendix for a machine where `.venv` or
`tests/conftest.py` is unavailable, and it was run **verbatim from the document** rather than typed
again: the extracted block printed `indexed True` and two tokens, `/readyz` answered `ready`, and
`check` returned the same ten `ok` lines. The appendix says what it cannot replace: the packet still
comes from `walkthrough.py packet`, because a hand-written builder would be the second source of
truth described above.

## Gate rows

| Row | Reading | Verdict |
|---|---|---|
| V2-B6 (external reader walkthrough) | pack prepared, nobody has sat down | still `not-run` |
| T4 (owner action) | `up` and `check` replay the runbook's ten readings on a clean machine; the readers remain the owner's to name | prepared, not closed |

## What this does not prove

- **No human has used it.** The 90-second judgement (V2-D3), the wording readers actually stumble on,
  and whether `cannot_be_bounded` reads as a result rather than a failure are all unmeasured. A tool
  that makes the room ready is not evidence about the room.
- **Two of the three verdicts stay unreachable.** Every certificate in this corpus has an empty
  feasible set, so `bounded_supports` and `bounded_refutes` cannot be exercised by a reader here.
- **`check` does not look at the print.** A4, hidden controls and a complete result are only visible in
  the reader's print preview; step 4 still records them by hand.
- **One deployment shape.** SQLite on localhost or a LAN. The PostgreSQL path is covered by
  `tests/test_migrate_postgres.py` and the container job, not by this pack.
- **`check` is coupled to the corpus on purpose.** `QUESTIONS` and `CERTIFICATES` are constants; if the
  fixture packet changes, the tool must change with it, and the test that compares bytes will be the
  first thing to say so.
