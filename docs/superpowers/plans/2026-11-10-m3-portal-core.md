# M3 — Portal core (2026-11-10)

One plan per milestone, tasks at test-cycle size. This document is the task
list; the PRD is the spec. Baseline is the frozen ledger Section 7
(`51e1294`), captured by re-running Section 0.4 at `386dc9e` **before** any
source edit: B3 `649 /649` corpus present, and a measured clean-clone
corpus-absent `612 /612` (both rc 0).

## 1. What Section 7 says M3 is

> **M3** Portal core | auth, orgs/projects, F1 ingest, F2 certificate view,
> F3 slice view, provenance drawer | portal | AC2, AC3, AC13, AC14; the frozen
> repo's committed artefacts render correctly end-to-end; parity job (6.3)
> green | read-only deployment first (no policies yet)

§4.2 fixes the stack: FastAPI serving REST + a built single-page client from one
process, SQLAlchemy on SQLite (PostgreSQL by one env var), Alembic, Pydantic.
§6.1 turns **I1** and **I3** `ACTIVE (M3)`; I2/I5 stay `ACTIVE (M2)`, I6 stays
`ACTIVE (M1)`, I4 stays `UNPROVEN (M4)`. §6.2 forbids skip/xfail/ignore/
exemption, and requires a plant to prove both that the removal landed and that
the guarded comparison fired, with observed counts.

Integration convention, measured per §0.2 item 2 before writing any integration
command: portal `git log --merges --oneline | wc -l` = **0**,
`git rev-list --count HEAD` = **10** → rebase plus `--ff-only`; this plan uses
linear pushes to `main`, no merge commits.

## 2. What M2 already has, and what M3 still owes

M2 delivered: `packet build|verify|html`, `manifest.py` (Pydantic contract with
a named refusal for unknown `manifest_version`), `registry.py` (AC14
idempotence), `replay.py` (the only module allowed to `import subprocess`),
`engine.py` (`RunRow` + the four states), `distributions.py` (pin registry),
`emit.py` (I2 enforced at emit), `doctor.py`, and 31 plants.

M3 still owes: a database and its migration; org/project scoping; human and
token auth with the §4.5 role matrix and an audit row per mutation; F1 ingest
over a real bundle; F2/F3 views over parsed artefacts; the provenance drawer;
AC2/AC3/AC13/AC14 on the web surface; §6.3 parity against the frozen repo's
committed artefacts; and the I1/I3 plants in CI.

The first source task is the **follow-up** F2 from the M2 closure: add
`started_at` to `RunRow`. It is not functional feature F2 (certificate view).

## 3. Modules and tasks (each task is one red/green test cycle)

| # | Module / file | Test first | Then implement |
|---|---|---|---|
| T1 | `engine.py` — follow-up F2 | `test_engine.py`: row carries a non-empty ISO-8601 `started_at`; two attempts have two timestamps | add the field, keep every invariant-carrying field and the four exit codes unchanged |
| T2 | `db.py` — SQLAlchemy models | `test_db.py`: tables match §4.3; `certificate_summary` has no `AVG`/aggregate write path; queries scope by `project_id` | models for org, project, packet, artifact, certificate_summary, run, user, membership, api_token, audit_row; SQLite default, `AUTHORATE_DB_URL` override |
| T3 | `migrations/` — Alembic | `test_migrations.py`: `alembic upgrade head` on an empty file DB reproduces `Base.metadata` tables | one revision, offline-capable `env.py`, no hand-written CREATE outside the migration |
| T4 | `auth.py` | `test_auth.py`: viewer cannot ingest; producer can; unknown/absent token → 401; role from membership, not from the request body | session cookie for humans, project-scoped API tokens (hash only stored), §4.5 matrix as one function, audit row on every mutation |
| T5 | `ingest.py` (F1) | `test_ingest.py`: manifest parse, every path present, every sha256 matches, `protocol_digest` present; named refusals for tampered byte / `..` traversal / over-cap / duplicate case id; re-ingest is one row (AC14); embedded wheel hash mismatch → `unverified_provenance` | unpack tar/zip to a temp dir, refuse the whole packet on any failure, index only after every check passes, parse certificates into `certificate_summary` **without arithmetic** |
| T6 | `views.py` (F2) + `emit.py` reuse | `test_views_f2.py`: AC2 all-refusal packet renders the verbatim reason, no `0`/blank/`no data`; AC3 the number carries unit, budget, `n_cal`/`n_eval`, packet id and protocol digest in the same component; missing field → "not published by this certificate"; `closest_attempt` only under the labelled disclosure | render states as an enum with no numeric fallback; every number goes through `emit.statistic` (I2 already enforced there); provenance-mismatch banner naming both digests with the number struck through |
| T7 | `views.py` (F3) | `test_views_f3.py`: pooled + companion side by side; pooled alone → `no_slice_evidence`; each slice prints its own denominator; a refusing companion heads its panel; shared-item structure printed or `independence not established`; degenerate single-value key excluded with a note; over-cap → top-N by smallest `n` + "and K more" | read declared slice keys from the artefact, never compute a correction |
| T8 | `app.py` + `web/` | `test_api.py`: AC13 viewer GET records artefact → 403 **and** an audit row naming the denial; every mutating endpoint writes an audit row; `/healthz` and `/version` | §4.4 minimum routes, static single-page client served by the same process, project-scoped queries, no cross-project aggregate endpoint exists at all |
| T9 | `tools/parity.py` (§6.3) | `test_parity.py`: an explicit fixture list whose absence fails with the missing name printed (a glob-built list must be rejected); rendered values byte-equal after formatting; `verify`'s `re-derived N /M` quoted in the UI equals a live run in the same job | read the frozen repo's committed artefacts, ingest, render, compare; wire as a third CI job |
| T10 | `tools/plants.py` | extend the harness with M3 plants, all runtime-landed, red, restored, with sha256 receipts | I1 (`sum`/`AVG` writing `certificate_summary.bound`), I3 (refusal → zero/blank), I2 (`bound_unit` dropped), F1 (hash mismatch accepted), F3 (silent truncation), AC13 (viewer reads records), parity (glob list) |
| T11 | `doctor.py` | `test_doctor.py`: §4.6 prints version, DB backend, pinned version resolvable, Docker/`uv`, one self-test replay | extend the existing seven checks without changing the three M2 exit states (0 / 3 / 3) |

## 4. States and exit codes

No new exit codes. Reuse `EXIT_OK=0`, `EXIT_REFUSED=4`, `EXIT_NOT_RUN=3`.
A refusal on ingest is `rc 4` with a named reason, never a partial index; an
auth denial is HTTP 403 with an audit row, not a substitute for a render state.
`not-run` remains the only honest state when the environment cannot execute.

## 5. Plants (must all fire in M3's CI, then be restored by hash receipt)

I1, I3 (the two invariants turning ACTIVE), plus I2 regression, F1 integrity,
F3 truncation, AC13 isolation and parity fixture-absence. §6.2: prove the
removal landed **and** the guarded comparison fired; record observed counts.

## 6. Gate table (Section 13.1, counted not described)

Frozen-repo NIF (`649 /649`, unchanged from B3) · published-artefact diff
(`data/` 0; `docs/` 1 — this milestone's ledger opening, the counted
exception) · new-file coverage by explicit path · corpus-absent export lane
(146 tracked paths, `612 /612`) · portal suite 0 failures · 31 + N plants each
red and restored · parity byte-equal, missing fixture fails by name ·
clean-machine replay · leak test (§0.3) with no unlabelled hits · every cited
exit code from its own command. Plus M3-specific: AC2, AC3, AC13, AC14 asserted
on the web surface, and the liveness table with I1/I3 `ACTIVE (M3)`.

## 7. Deliberately not in M3

M4: claim check (AC5/AC6), auditor export (AC7), localization. M5: policies,
monitor/drift, in-browser verifier, `--format json` freeze round. No change to
any file `verify` compares (§0.5 NIF). No endpoint computing a bound (I1,
§3.4 NG7). No cross-project aggregate endpoint (§4.3). No outbound message to
a named third party and no irreversible public exposure (§0.2 (a)/(b)). No
hosted demo (§12.3 A5).

## 8. Stop point

Section 13.5: stop for the owner's approval at the Section 13.1 gate table,
with the Section 13.2 ten-section report and liveness table. M2's approval is
not carried forward. The same conversation window held M2's closure and this
M3 opener; the frozen ledger Section 7 records that disclosure for the owner
to accept or refuse at the gate.
