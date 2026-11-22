# V1 — Offline replay, one vocabulary, fail-closed defaults (2026-11-17)

One plan per slice, tasks at test-cycle size. This document is the task list; the blueprint
(`docs/2026-11-17-autorate-evolution-blueprint.md` in the workspace) is the argument. Baseline
captured before any source edit, per the repository's own convention.

## 1. Owner decisions this slice is built on

Accepted 2026-11-17 ("都听你的"), recorded here so a later session does not re-litigate them:

| ID | Decision | Chosen | Reversal condition |
|---|---|---|---|
| D1 | Slice order | Offline first, then audience | A pilot customer requires UI-first |
| D3 | State vocabulary | Qualifiers, no protocol rename | Two or more external misquotes |
| D4 | Wheel in packet | Dual channel; offline requires a local wheel whose hash is recorded | First customer requires single-file delivery |

The blueprint's A-01 丙 / A-02 甲 are therefore in force. D2 (naming an external reader) is an
owner action outside this repository and is **not** claimed by this plan.

## 2. Baseline (measured before edits)

- Portal tip `21c5c9c`, working tree clean.
- Suite: **303 passed** before the change; **311 passed** after T1/T2 (six configuration-guard
  tests, two README-claim tests), measured 2026-11-17. The count is from the run, not copied.
- Lint: `ruff` over `src tests tools` with the CI selection → all checks passed.
- Frozen repo at `5e76fcd`: `autorate verify --protocol protocol.json` → rc 0,
  `re-derived 649 /649 values`, protocol `ce43f8e29cc1`.
- Known holes this slice closes (blueprint §1.3, §5.4, §6.4):
  1. `create_app()` starts with the packaged salt and the literal `dev-only` secret when the
     environment omits them — share links and sessions become forgeable by anyone who reads the
     source.
  2. The portal README still describes the repository as M2 and says M3–M5 are not implemented,
     while policies, monitors, admin, four migrations and the HTTP API are present.
  3. No channel label distinguishes a replay that used the network from one that did not.

## 3. Tasks

### T1 — F-07: refuse the packaged credentials at construction
1. Red: `create_app()` with neither argument nor environment variable raises a configuration
   error naming **both** missing variables, and the message does not quote any value.
2. Red: an environment variable set to the packaged default is refused, not accepted.
3. Red: an empty or whitespace-only value is not a credential.
4. Green: a resolved pair of non-default values constructs the app; explicit arguments still win
   over the environment (the test seam every existing fixture uses).
5. Guard: the configuration check runs **before** the engine is created, so a misconfigured
   deployment fails without touching the database file.
6. Negative control: remove the default comparison and the published-default test must go red.

### T2 — X-02 (first half): the README states what this repository is
1. Rewrite the milestone paragraph to describe M1–M5 as shipped, naming the three surfaces that
   exist (packet/replay, portal API, policy/monitor/admin).
2. Add `monitor` to the command table; it exists in the CLI and is absent from the table today.
3. Red: a test asserts the README does not contain the retired sentence "M3–M5 ... not
   implemented". The test reads the prose, not a rendered page, so it fails on a doc edit only.
4. Do **not** add a test that pins every sentence: a documentation test that has to be edited on
   every wording change gets deleted, and a deleted guard is worse than a narrow one.

### T3 — X-01: a channel label on every replay

Depends on T5: until a local wheel can be supplied, the `offline` value is unreachable and the
label would only ever print `online` — a field that cannot take two values is not evidence.

1. The replay outcome carries the channel it used: `online` when the wheel was fetched, `offline`
   when a local wheel was supplied. `not-run` carries the channel it *would* have used.
2. `doctor` prints the channel beside the backend it probed; the run row records it as an additive
   field (old rows read back as `unknown`, never as `online`).
3. Red: a run row written by this build carries the field; a row written without it reads back as
   `unknown` and the view says "channel not recorded" rather than implying either.
4. Envelope: this is a run-row field, not a certificate field — the frozen surface is untouched.

### T4 — A-06: one image, one self-check
1. A container definition that installs the locked environment, runs the migrations, and then
   `doctor`; no credential is baked in and the start refuses without the two variables from T1.
2. Red: a test reads the container definition and asserts it (a) does not copy a `.env`, (b) runs
   the migration step before the server, (c) ends at `doctor`/server rather than a shell.
3. The image is **not** published by this task; building it is a local gate, publishing is an owner
   action (the blueprint's §6.4 rollback rule).

### T5 — F-01/A-01: the offline branch
1. `packet build` gains an offline mode: the pinned wheel is embedded under a reserved path, its
   sha256 is recorded in the manifest, and `records` artefacts remain excluded for shareable
   packets.
2. Manifest schema version bumps; the parser accepts the previous version and reports which one it
   read (dual-read for exactly one version).
3. `verify-packet` in offline mode never resolves the index: a test injects a fetcher that raises
   if called, and the replay must still complete from the embedded wheel.
4. Red: a manifest that claims an embedded wheel whose bytes do not match the recorded hash is
   refused with both hashes, before anything executes.
5. Licence check is a **precondition**, not a task: if redistribution of the dependency tree is
   refused, this task stops at "record the hash, do not embed" and T3's label carries the gap.

### T6 — A-02: one vocabulary, qualifiers only
1. A single mapping module translates each layer's state into a display term:
   `statistically feasible` (CLI), `replay-consistent` (run row), `badge green` (action),
   `holds` (monitor) — four names that no longer share the word `certified`.
2. Red: a test asserts every state tuple in the four modules is covered by the mapping, and that
   adding a state without a mapping fails.
3. Red: the web page and the share HTML never print the bare word `certified`; they print the
   qualified term and the packet id.
4. Do **not** rename the enum values or the protocol: the frozen surface and old packets stay
   readable; the qualifier is a display contract.

### T7 — V1 gate
1. On a machine with no route to the index, a packet built in offline mode replays to
   `re-derived N/N` with the embedded wheel, and a packet without one yields a named `not-run`
   listing the missing prerequisite — never a pass.
2. `create_app()` refuses the packaged defaults; the README's milestone paragraph matches the
   shipped surface; every replay prints its channel.
3. Frozen repo untouched: `git diff --name-only -- data/ docs/` is empty and `verify` still prints
   the same denominators.

## 4. Deliberately not in this slice

Login/session issuance, first-screen redesign, print view, monitor scheduler, any new certificate
family, any signature or transparency-log work. V2 owns the first four.

## 5. Dependencies and risks

- T5 depends on the licence review in the blueprint's D4; without it, the task degrades to
  hash-only and the offline channel reports the gap instead of closing it.
- T3's run-row field is additive; a row written by an older build must read back as `unknown`.
  The temptation to default it to `online` is the failure mode this task exists to prevent.
- T2's test is intentionally narrow. Broad prose assertions are how documentation tests become
  decorative.

## 6. Gate table

| Row | Command's own result | Pass condition |
|---|---|---|
| B1 | portal suite | all tests pass; count recorded from the run |
| B2 | negative controls | 55/55 red, restored, no leftover |
| B3 | frozen verify | rc 0, denominators unchanged from §2 |
| B4 | offline replay | `re-derived N/N` or named `not-run`, never a pass |
| B5 | default credentials | construction refused, message names both variables and quotes neither value |

## 7. Progress at 2026-11-17 22:20

| Task | State | What proves it |
|---|---|---|
| T1 | done | `tests/test_config_guard.py` — six tests; construction is refused before the engine exists |
| T2 | done | `tests/test_readme_claims.py` — two narrow assertions; the old paragraph is red against them |
| T5 | done (first implementation) | `tests/test_offline_packet.py` — twelve tests: schema 2, wheel-set contract, offline container/uv, online path unchanged |
| T3 | done | `channel` on every run row and in `doctor`; a row without it reads back `unknown` and `runs list` says how many such rows it found |
| T4 | done (image build unverified) | `Dockerfile`, `.dockerignore`, `serve` command, five tests; no Docker daemon on this machine, so the definition is checked but never built |
| T6 | done | `vocabulary.py`, qualified display terms, nine coverage tests; catalog values changed, machine values did not; the badge's visible label is `verify passed` (the blueprint's `badge green` was a label for the slot, not a sentence a reader can act on) |
| T7 | done (one row still not-run) | `docs/verification/2026-11-17-v1-gate.md`: B1/B2/B3/B4/B4′/B4″/B5/B7 pass; B6 (image build) remains `not-run` |
| T8 | done | manifest records `wheel_platforms` derived from the wheels; a `win_amd64` set is refused before install; an install failure names the target image |
| T9 | done | `tools/plants.py`: 55/55 red, 55/55 restored, no leftover markers |

Suite: 303 before the slice, **348 after T1–T9**. Lint: CI selection, all checks passed.

The I1 static guard caught a `sum()` in the new CLI counter during the first full run and the suite
went red; it was replaced with a list length. That is the guard doing its job, recorded here because
a gate nobody ever trips is indistinguishable from no gate.

**T4 findings and one deviation.** The portal had **no server entry point and no server dependency**
before this task: `create_app` existed, nothing launched it, and `uvicorn` was in neither
`pyproject.toml` nor `uv.lock`. `autorate-portal serve` and the dependency are therefore part of T4,
not an extra. The image does **not** run `doctor` at startup, which is a deliberate departure from
§3: doctor's required rows are replay prerequisites (Docker, PyPI), and gating a server on them
would make an air-gapped deployment refuse to boot — the opposite of what V1 is for. The startup
gate is instead: credentials refused before a socket exists (T1), migrations before the server, and
a `/healthz` healthcheck. `serve` itself does not verify the database's migration head; the image's
migration step is the enforcement point, and a bare `serve` on an unmigrated database is a
deployment error. **Amended 2026-11-22:** the sentence above used to name `alembic upgrade head &&`
and to say the healthcheck would surface an unmigrated database. Both are wrong now, and the
second was wrong when written: `/healthz` returns a constant and never touches the database, so it
stays 200 on an empty one. The step is `autorate-portal migrate --if-enabled &&`, which takes a
schema lock so replicas may start together (see `autorate_portal.migrate` and
`docs/verification/2026-11-22-postgres-and-container.md` §P9-P12). Turning that step off with
`AUTHORATE_MIGRATE_ON_START=0` is only safe when a job has already run the migration: nothing in
the image detects the reverse order.

**T5 deviation, recorded rather than hidden.** The unit is a **wheel set**, not a single wheel.
`autorate` depends on `numpy`; embedding only the pinned wheel would still send `pip` to the index
for the dependency, which is the failure this task exists to remove. `--embed-wheel` is repeatable,
the builder refuses a set that omits the pinned wheel or whose pinned bytes disagree with the
declared hash, and the replay installs with no index from that directory. Schema 1 packets are
byte-identical to before; schema 2 is written only when a set is embedded.

Two limits stay stated: the container backend still needs Docker (the image itself may be local),
and `doctor` has not learned to read a packet's schema yet, so `doctor --packet` will still report
the network check as failed for an offline packet. T3/T4 own that correction.


## 8. Follow-ups found and closed

**T8 — wheel platforms, closed.** Schema 2 now records `wheel_platforms`, derived from the wheel
filenames and re-derived by the parser (a manifest whose field disagrees with its artefacts is
refused). The uv backend checks every embedded wheel against `packaging.tags.sys_tags()` before
installing and refuses a mismatch with both the wheel's platforms and the packet's declared set; a
failed install on either backend is named with the target image instead of surfacing as `exited 1`.
Portability is still per-platform: the macOS packet needs a macOS wheel set, and the gate says so.

**T9 — the 55 plants, closed.** All 55 landed at runtime, went red, and were restored byte for
byte, with no leftover markers. This is the row that would have caught a guard made inert by the
slice's many edits to `replay.py`, `app.py`, `manifest.py` and `packet.py`.

The only open V1 row is **B6**: the image has never been built, because this machine has no Docker
daemon. That is an environment fact, not a design gap, and it stays `not-run` until a machine with
a daemon runs it.
