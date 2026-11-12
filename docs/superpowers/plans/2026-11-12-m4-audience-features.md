# M4 — Audience features (2026-11-12)

One plan per milestone, tasks at test-cycle size. This document is the task
list; the PRD is the spec. The baseline is the frozen ledger Section 9
(`fd06bf9`, M4 opening committed as `972c107` and pushed to both remote
branches), captured by re-running Section 0.4 **before** any source edit: B3
`649 /649` corpus present, and a re-executed clean-clone corpus-absent
`612 /612` (both rc 0). The portal opens clean at `d0400b4`.

## 1. What Section 7 says M4 is

> **M4** Audience features | F4 claim check, F5 audit export,
> badge-as-shareable, localization pass (Section 11's `Localization` row;
> second language fixed by A6) | portal | AC5, AC6, AC7, AC8, AC11; a P1 and a
> P2 walkthrough completed with an external reader | F4/F5 are additive views
> over M3's data

A6 (§12.3) fixes the second language as **Simplified Chinese (`zh-Hans`)**,
shipped through **one message catalog**. §6.1 turns **I4** `ACTIVE (M4)`; I1/I3
(`ACTIVE (M3)`), I2/I5 (`ACTIVE (M2)`), I6 (`ACTIVE (M1)`) must not regress.
§6.2 forbids skip/xfail/ignore/exemption and requires each plant to prove both
that the removal landed and that the guarded comparison fired, with counts.
§0.5 NIF: no change to `data/` or to a file `verify` byte-compares. §0.2
carve-outs (a) and (b) remain in force: no irreversible public exposure, no
outbound message to a named third party.

Integration convention, measured per §0.2 item 2 before writing any integration
command: portal `git log --merges --oneline | wc -l` = **0**,
`git rev-list --count HEAD` = **27** → rebase plus `--ff-only`; this plan uses
linear pushes to `main`, no merge commits.

## 2. What the published artefacts actually allow F4 and F5 to say

These are measured facts about the frozen repository's committed artefacts, not
design choices. They bound the implementation and must not be blurred in the
report.

1. **The audit lane publishes Markdown, not JSON.** `docs/AUDIT.md` is in the
   packet artefact plan; there is no `data/*audit*` JSON. F4 may *quote* it, and
   must label it as a document, never parse a machine-readable bound out of it.
2. **No certificate publishes a certified `autorate`.** Of the seven
   `data/cert_*.json`, six are `feasible=false` with `autorate=null` and the
   seventh (`cert_severity_ordinal.json`) is `feasible=true` but has **no
   `autorate` key at all**. No certificate has a top-level `bound_unit`, and no
   certificate has a key named `confidence`. Consequence: **AC5's
   `bounded_refutes` cannot be produced end-to-end from this repository's own
   packet.** It is proven by a synthetic certificate fixture that publishes a
   certified `autorate`, exactly as M3's F6 accepted that a per-group bound
   exists only in tests. The end-to-end path over the real packet answers
   `cannot_be_bounded`. The report names both; it does not claim the real packet
   refutes anything.
3. **The feasibility arithmetic has no `n_min`.**
   `data/g1_feasibility.json` top level is `producer, reference, rows, rubric`;
   `reference[]` publishes `n`, `k_max`, `largest_certifiable_error_rate`,
   `required_observed_accuracy`; `rows[]` publishes `missing_pool_input` (a
   verbatim statement of what is missing) and `n_cal_cases` / `n_eval_cases`.
   There is **no `n_min` or `required_n` key**. F4 rule 3 therefore reads the
   need from `missing_pool_input` and the published size ladder, and where the
   artefact states no required sample size it says so instead of inventing one.
   `docs/FEASIBILITY.md` L142-145 names the missing pool error count.
4. **The comparability statement is published by the audit lane.**
   `docs/AUDIT.md` L10 states that the name `confidence` is carried on two
   scales by two harnesses and that "A field name therefore does not say which
   quantity a file holds; only the program that wrote it does"; L132 says
   "Quoting either multiple as the other is the definition slip". AC6 quotes
   these verbatim; the portal does not paraphrase them into a weaker claim.
5. **`protocol.json`'s `known_limits` is a two-element array**, verbatim:
   `"exchangeability within group assumed; none of it is usable here"` and
   `"no certificate exists, so no action is certified"`. F5 renders it as its
   own section in every bundle, with the mapping present rather than
   configurable away.
6. **Measured vs implied vs point estimate.** `docs/AUDIT.md` prints `0.15` as
   an *implied* error rate (`1 - 0.85`), measured row rates (e.g. `0.5000` on
   `2 of 64`), exact one-sided upper bounds (`0.9747`), and at L133 says a
   multiple "is a point estimate and needs its interval before it is anything
   else". L134: "Nothing here certifies a deployment". F4 labels each class and
   outputs **no point estimate the packet did not publish** (F4 rule 4).
7. **A kind-name inconsistency in the PRD.** §5 F5 says `generic_aap`; §4.3's
   schema and the existing `db.EXPORT_KINDS` say `aap`. §13.3 item 3 fixes
   spellings and §0.5 forbids editing the frozen PRD, so M4 ships §4.3's
   `annex_iv | iso_42001 | aap` and registers the discrepancy as a deviation
   for the owner, not a silent alias.
8. **AC11 sits in M4's gate while F7 (policies) is M5's deliverable.** M3's D1
   already said policies stay with M5. M4 therefore builds the *minimum
   read-only SDK surface* AC11 needs — `GET /api/v1/policies/{id}.well-known`
   returning `state: stale` and `strict=1` → 409 — over the existing
   `db.Policy` row, and leaves creation, editing, versioning and SDK
   enforcement to M5's F7. The report names this scope cut explicitly.
9. **The P1/P2 walkthrough is an open gate row.** The opener and ledger §8
   (dated 2026-11-12) record that no external reader is named. It cannot be
   closed by the author, a reviewer or CI; no substitute or softened reading is
   proposed. It blocks **approval**, not the work. This plan builds to the gate
   and stops there.

## 3. Modules and tasks (each task is one red/green test cycle)

| # | Module / file | Test first | Then implement |
|---|---|---|---|
| T1 | `claims.py` — F4 core | `test_claims.py`: the closed verdict enum (`bounded_supports`, `bounded_refutes`, `cannot_be_bounded`); a synthetic certificate publishing a certified `autorate` and a claim above it → `bounded_refutes` with both numbers and both units (AC5); no invented point estimate; every verdict carries a provenance line (I2/F4 rule 5); no packet → the one F1 command | parse a structured claim (share, field, unit, population); compare only against published certificate rows or the quoted audit document; carry `bound`, `denominator`, `reason` on all three verdicts; never compute a rate |
| T2 | `claims.py` — audit lane + AC6 | `test_claims_audit.py`: a claim on `confidence` → `cannot_be_bounded` plus the verbatim comparability statement (AC6); the audit lane is labelled Markdown, not parsed as JSON; `0.15` is labelled implied; `cannot_be_bounded` names `missing_pool_input` from `g1_feasibility.json` and the size ladder, and when no required sample size is published says so | quote `docs/AUDIT.md` L10/L132/L134 out of the packet's own bytes; read `g1_feasibility.json` for the published feasibility arithmetic; no `n_min` is invented |
| T3 | `exports.py` — F5 | `test_exports.py`: three kinds; a line without a source path fails the bundle build; every line names path, sha256, protocol digest and packet id; `known_limits` is its own non-omittable section; byte-identical double build (F5 rule 4) and the export records its own hash; actor and target logged; a heading with no mapping emits `no evidence published`; AC7 blocked with the run id | build from the stored bundle and `certificate_summary` rows only; explicit heading→source template; re-verify source digests before building; read the mismatch `run` row when one exists, and say plainly when none does |
| T4 | `app.py` — the two §4.4 endpoints | `test_api_claims_exports.py`: `POST /api/v1/claims/check` and `POST /api/v1/exports/{kind}` scoped by the caller's project; viewer → 403 with an audit row; compliance/auditor/admin may export; every mutation writes an audit row; no cross-project aggregate | wire T1/T3 behind §4.5's `EXPORT_AUDIT` capability and `auth.require`; reuse `guard` and `record_audit` |
| T5 | `trend.py` — I4 / AC8 | `test_trend.py`: two packets at different `protocol_digest` values → no trend unless a boundary is drawn and both digests are named (AC8); within one digest a series is allowed; the §6.2 plant "seed two packets at different digests and open a trend" fires red | query layer refuses a series spanning two digests without a boundary marker; a drawn boundary prints both digests and the separating line; no delta is computed (I1) |
| T6 | `policies.py` — AC11 minimum | `test_policies.py`: a policy whose packet was superseded → `state: stale` in the SDK payload; `strict=1` → 409 with the reason; an active policy → 200; the `.well-known` read is unauthenticated as §4.4 requires | read the existing `db.Policy` row; staleness from a newer `protocol_digest` in the same project; no create/edit/version endpoints (M5 F7) |
| T7 | `badge.py` — badge-as-shareable | `test_badge.py`: the closed F8 vocabulary (`certified`, `not-certifiable`, `drift`, `not-run`), never a boolean; the shareable artefact carries packet id, protocol digest, denominator line and state; **zero records rows** (§8.4); `unverified_provenance` is carried into the shareable copy (F9 rule 4b); deterministic; no network call and no publish action (§0.2 (a)) | generate a self-contained shareable badge (JSON plus SVG) from published fields; reuse the frozen repo's badge record shape; F9's share link stays M5 |
| T8 | `i18n.py` + one catalog | `test_i18n.py`: `en` and `zh-Hans` key sets are equal (catalog completeness); numbers are never string-concatenated; unit words `case`/`record` are translated, and a mistranslated unit fails the test; refusal/certified/verdict words exist in both languages | one JSON message catalog, `t(key, **kwargs)`, all display text through the catalog; values stay unformatted digits from the artefact |
| T9 | `views.py` / `html.py` / `web/index.html` — localization pass | `test_views_locale.py`: F2 renders in both locales, refusal differs in **text** as well as hue (WCAG 2.1 AA); F4 verdict card localized; keyboard-reachable controls; CI writes both locales' F2 renderings as artifacts | thread `locale` through the renderer with `en` as default; `lang` attribute; no numeric recomputation; the SPA gains a locale switch |
| T10 | `tools/plants.py` | `test_plants.py` unchanged in spirit; extend the harness with M4 plants, each runtime-landed, red, restored, with sha256 receipts | I4 (cross-digest trend drawn), F4 (invented point estimate / comparability dropped), F5 (`known_limits` omitted / source-less line accepted), AC7 (stale source exported), badge (records leak), i18n (unit mistranslated), AC11 (stale swallowed) |
| T11 | `tools/parity.py` + `.github/workflows/ci.yml` | `test_parity.py` extended: F4/F5 published values byte-equal after formatting; the three CI jobs stay green; a fourth step writes both locales' F2 renderings as CI artifacts | §6.3 parity against the committed artefacts; explicit fixture list whose absence fails by name; no glob |
| T12 | gate script + §13.2 report + fresh review | `m4_gate_run.sh` counts every §13.1 row; the report has all ten §13.2 sections and the liveness table; a fresh reviewer reads the diff and the section list | report lands at a unique path in `~/laya-evidence/m4-2026-11-12/` **before** it is summarized; gate table carries the open P1/P2 row; stop for the owner |

## 4. States, vocabularies and exit codes

No new CLI exit codes: `0` ok, `2` usage, `3` not-run, `4` refusal/mismatch.
F4's verdict vocabulary is closed at exactly three values. F8's badge
vocabulary is closed at exactly four. A claim the packet cannot bound is a
`cannot_be_bounded` result, never a pass, a zero or a blank card (I3). An
environment that cannot execute produces a named `not-run` (§6.2). A policy
denial is HTTP 403 with an audit row; `strict=1` on a stale policy is 409.

## 5. Plants (must all fire in M4's CI, then be restored by hash receipt)

I4 is the invariant turning `ACTIVE (M4)`; its §6.2 plant is "seed two packets
at different digests and open a trend". Plus I1/I2/I3/I5/I6 regressions, F4,
F5, AC7, the badge privacy rule, i18n and AC11. §6.2: prove the removal landed
**and** the guarded comparison fired, and record observed counts, not booleans.
No skip, xfail, ignore or exemption is introduced.

## 6. Gate table (Section 13.1, counted not described)

Frozen-repo NIF (`649 /649`, unchanged from B3) · published-artefact diff
(`data/` 0; `docs/` 1 — the M4 ledger opening, the counted exception) ·
new-file coverage by explicit path · corpus-absent export lane (146 tracked
paths, `612 /612`) · portal suite 0 failures · plants each red and restored ·
parity byte-equal, missing fixture fails by name · clean-machine replay ·
leak test (§0.3) with no unlabelled hits · every cited exit code from its own
command. M4-specific: AC5, AC6, AC7, AC8, AC11 each from its own command; the
liveness table with I4 `ACTIVE (M4)`; known-limits and comparability checks;
the two-locale artifact; the deterministic double-build.

**Open row, carried unchanged from the opener:** P1 and P2 walkthroughs with an
external reader — **not satisfiable by the author, a reviewer or CI**, no
substitute proposed. It remains open in the gate table and blocks approval.
The gate table is therefore presented as *built to the gate*, not as a
complete gate.

## 7. Deliberately not in M4

M5: F6 monitor/drift, F7 policy creation and versioning, F9 share link and
in-browser verifier, F10 administration, the `--format json` freeze round. No
change to any file `verify` compares (§0.5 NIF). No endpoint computing a bound
(I1, §3.4 NG7). No cross-project aggregate endpoint (§4.3). No outbound
message to a named third party and no irreversible public exposure (§0.2
(a)/(b)). No hosted demo (§12.3 A5). No coverage floor (M2 F3 / M3 F3, still
no guard to lower). AC5 is **not** claimed against the frozen repository's own
packet: that packet publishes no certified `autorate`. M3's approval is **not**
carried forward.

## 8. Stop point

Section 13.5: stop for the owner's approval at the Section 13.1 gate table,
with the Section 13.2 ten-section report and liveness table. The report is
written to disk before it is summarized. The P1/P2 external-reader row stays
open; naming that reader is the owner's act, and this session neither closes it
nor proposes a substitute.
