# M5 — Enforcement, monitor, in-browser verifier, `--format json` (2026-11-16)

One plan per milestone, tasks at test-cycle size. This document is the task list;
the PRD is the spec. The baseline is the frozen ledger Section 11 (`f5eb3cd`,
M5 opening committed as `0db1fd8` and pushed to both remote branches), captured
by re-running Section 0.4 **before** any source edit: B3 `649 /649` corpus
present, clean-clone corpus-absent `612 /612`, both rc 0. The portal opens clean
at `318f80d`, suite green.

## 1. What Section 7 says M5 is

> **M5** Enforcement, monitor, in-browser verifier, `--format json` | F6, F7, F9,
> F10; Pyodide certificate self-checker reusing the *published* `verify` module;
> the frozen repo's `--format json` as one freeze round | portal + **frozen repo**
> | AC12; browser checker's verdict equals the container replay's for the same
> packet; freeze round for `--format json` passes with denominators **unchanged**
> and a recorded justification for adding a compared field or not | the browser
> checker must degrade to "replay required" if the wheel cannot be fetched

Two **entry conditions** from ledger Section 10, fixed before M5 is called done:
**W-F1** — the one `certified` row's detail renders
`bound: not published by this certificate` while the artefact publishes `bound`;
**W-F2** — the detail group panel shows `n_cal=1487` for every row without
naming whose dataset those groups are.

§6.1's six invariants are **UNPROVEN at M5** until each plant is re-run in this
milestone's CI; I1/I3/I4 keep their M3/M4 shapes. §6.2 forbids skip/xfail/ignore,
requires each plant to prove both that the removal landed and that the guarded
comparison fired, and keeps gate values out of `HEAD`. §0.5 NIF: only the
single authorised `--format json` round may touch the frozen surface.

## 2. Measured facts this plan is built on (re-derive, do not assume)

1. **`data/cert_severity_ordinal.json` publishes a top-level `bound`** —
   `0.045180414995`, `n_cal=600`, `n_eval=600`, `feasible=true`, `autorate`
   absent, **no `bound_unit` anywhere**. `ingest.summary_fields` reads only
   `conditional_error_bound` / `marginal_error_bound`, so `bound` lands NULL and
   F2 prints "not published by this certificate". That sentence is false about
   the artefact, and it is W-F1.
2. **`data/slices_language.json` publishes four groups, every one with
   `n_cal=n_eval=1487`** and `backend: laya`. The detail endpoint attaches that
   document to whichever certificate is opened (`_slice_document`), so a
   `jev`-backend or `synthetic-ordinal` certificate is rendered beside a group
   panel that belongs to `laya` — W-F2, and the panel never says so.
3. **`record_summary` refuses a bound without a unit** — correctly, because a
   number without its unit is not the claim the artefact made. W-F1's fix must
   therefore keep the refusal for *synthesised* values and still record an
   artefact-published bound whose unit is genuinely absent, so the view can say
   `unavailable: bound_unit` instead of "not published".
4. **`policies.py` is AC11's read-only surface only** (ledger D1): no create, no
   version, no `action`/`label`. F7 is additive to it, not a rewrite.
5. **`html.py` and `views.py` are two renderers today.** F9 rule 4 wants one
   component contract with two targets; the drift risk is exactly the defect
   class this project exists to prevent.
6. **The frozen CLI's `verify` prints five lines** (claims, protocol, inventory
   source, disclosure, `re-derived N /M`) and its comparisons happen before any
   formatting — so `--format json` adds a presentation, not a compared field.

## 3. Tasks

### T1 — W-F1: the certified row's bound is rendered, or its missing unit is named
1. Red: ingest the ordinal certificate's shape (top-level `bound`, no unit) →
   assert `summary.bound == "0.045180414995"` and the panel contains
   `unavailable: bound_unit` and not `not published by this certificate`.
2. Red: a certificate with `bound` and a unit still renders the number.
3. Green: `summary_fields` reads top-level `bound` third; `record_summary`
   accepts a unit-less bound only when the caller states the artefact published
   none (`unit_absent_in_artefact=True`), and still refuses an assembled number
   whose unit nobody stated.
4. Guard: the ingest refusal test for a bound with a fabricated unit stays red
   when the guard is removed.

### T2 — W-F2: the group panel names its source and its backend
1. Red: open the `jev` certificate against a packet whose only slice document is
   `slices_language.json` → the panel must print the source path and
   `backend: laya`, and must state that these groups are **not** this
   certificate's backend.
2. Red: a certificate whose own document carries the slices prints no mismatch
   note.
3. Green: `slice_rows` carries `source_path` / `source_backend`; `slice_view`
   renders a provenance line and, on a backend mismatch, a named note before the
   rows. No row's number changes; no denominator is invented.

### T3 — AC12: a records ingest that collides with the calibration pool is refused
1. Red: POST a records file whose `case_id` equals one in the packet's committed
   records → 409 naming the colliding id, the pool's artefact path, and the
   split-rollback consequence.
2. Red: a records file with no collision is accepted (201) and does not mutate
   any summary.
3. Green: `records_ingest` collects `case_id` values from the packet's records
   artefacts for the same backend; the refusal is a named 409 with an audit row.
4. Guard: removing the collision comparison makes the first test accept.

### T4 — F6 monitor: a scheduled replay, never an in-app calculation
1. Red: `autorate-portal monitor run --packet P --registry R` writes one `run`
   row and one `monitor_result` row, and leaves every `certificate_summary` byte
   unchanged.
2. Red: verdict vocabulary is the CLI's — rc 0 `holds`, 3 `not_certifiable`,
   4 `drift`, 2 `configuration_bug` (surfaced as a bug, not a red KPI); the
   alert copy quotes the tool's own `re-derived N /M` / `DRIFT:` line verbatim.
3. Red: environment unavailable → `not_run` carrying the doctor output; timeout
   → `not_run` plus the partial stdout hash; neither is ever `holds`.
4. Green: `monitor.py` + `db.MonitorResult` writer; no endpoint computes a bound.
5. Guard: making the monitor write `certificate_summary` turns test 1 red.

### T5 — F7 policies: versioned objects with an SDK payload
1. Red: create a policy naming packet + budget; `GET .well-known` returns
   `action`/`label` per decision, shaped like the CLI's `gate` output.
2. Red: editing creates a version (`version`, `supersedes`); nothing overwritten.
3. Red: a policy whose budget the certificate does not publish is refused naming
   the value; a slice value absent from the artefact is refused naming it.
4. Red: a monitor `drift` result makes the policy `stale` in the payload, and
   `strict=1` returns 409 with the reason (AC11 kept green).
5. Green: `policies.create_policy` / `edit_policy` / `sdk_payload` extension; one
   migration for the version columns.

### T6 — F9: one renderer, two targets, and a share link that expires
1. Red: `autorate-portal packet html` and `GET /api/v1/share/{token}` render the
   **same bytes** for the same packet and locale (one component contract).
2. Red: the share link carries its expiry and packet id; after expiry it is 410;
   it never embeds a records artefact; a shareable packet's
   `unverified_provenance` badge is rendered into the HTML.
3. Red: an artefact over the embed cap is omitted with its path named, and the
   page links out instead.
4. Green: `render.py` owns the document; `html.py` and the portal route call it;
   `share.py` owns tokens and expiry.

### T7 — F10 administration
1. Red per capability: orgs, projects, members/roles, tokens with scopes and
   last-used, retention, deletion (tombstone + byte removal), audit export, and
   the pinned-distribution registry (pin/upgrade). A viewer cannot manage any of
   them (403 + audit row).
2. Green: `admin.py` routes behind `MANAGE_MEMBERS`; default configuration needs
   no credential from this project.

### T8 — Pyodide self-checker, reusing the published module
1. Red: the page embeds no CDN, pins the wheel and its sha256, and its verdict is
   the published module's own (not a re-implementation).
2. Red: when the wheel cannot be fetched, the verdict is **`replay required`** —
   never a pass, never a red.
3. Green: `tools/checker/build.py` emits one HTML file; a node harness runs it
   against the same packet as the container replay and compares verdicts; the
   equality is recorded, not asserted.

### T9 — the frozen repo's one freeze round: `verify --format json`
1. Red: `autorate verify --protocol protocol.json --format json` emits one JSON
   object whose `re_derived` equals the human line's `N /M`, whose claims and
   protocol digest equal the human lines, and whose exit code equals the human
   run's.
2. Red: the human output without the flag is byte-identical to B3.
3. Green: `cmd_verify` builds a result object once, renders text or JSON from it;
   no comparison, field list or denominator changes. Justification recorded:
   **no compared field added**.
4. Gate: `re-derived 649 /649 values` unchanged; `git diff --name-only -- data/
   docs/` limited to the freeze round's own record.

### T10 — gate, liveness, report
Plants for I1–I6 re-run in this milestone; parity; both suites; the Section 13.2
report with the liveness table; stop for the owner at Section 13.1.

## 4. Exit-code and environment hygiene

Every cited exit code comes from its own command (`echo "NAME_EXIT=$?"` right
after its redirect). This session's sandbox refuses `mkdir` under
`/private/var/folders`, so pytest runs with `TMPDIR` inside the workspace; that
is an environment fact, recorded, not a test skip.
