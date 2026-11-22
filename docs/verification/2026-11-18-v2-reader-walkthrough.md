# V2 reader-walkthrough probe — 2026-11-18

**V2-B6 stays `not-run`.** No P1 (compliance) or P2 (procurement) who is not the author has
read this portal. What follows is a *machine-agent* drive of the same HTTP surface the browser
SPA uses, recorded so a future reader gate starts from evidence rather than from a claim. A
machine that can execute `fetch` is not a reader: it cannot be confused by a label, cannot
misread a refusal, and has no expectation to disappoint. The gate row is therefore not closed
by this document.

All readings below are captured on this machine on 2026-11-18 between 19:12 and 19:22 GMT+8
against a live service, not reconstructed.

## Environment

- portal working tree: same uncommitted V2 changes as the V1/V2 gates, plus the migration fix
  in §4; frozen repo `autorate` still clean (untouched).
- Python 3.13.13, Darwin arm64.
- Service: `authorate-portal serve --port 8111 --store /tmp/v2-walkthrough/store`,
  `AUTHORATE_DB_URL=sqlite:////tmp/v2-walkthrough/portal.db`,
  `AUTHORATE_TOKEN_SALT=walkthrough-salt`, `AUTHORATE_SECRET_KEY=walkthrough-secret`.
- Fixture data: project `prj-laya`, two users (`ada@example.test` compliance,
  `lin@example.test` viewer), one schema-2 packet (`pkt-ce1271fa3bdef759`, 35 artefacts),
  7 certificate summaries. Tokens are the throwaway pair in `/tmp/v2-walkthrough/tokens.txt`.
- Probe: `docs/verification/walkthrough_probe.py`, output `/tmp/v2-walkthrough/http/probe.json`.
  It drives the HTTP surface with `urllib` + a cookie jar; it is a stand-in, not a second
  implementation of the client.

## 1. What the agent did, and what it read

| # | Action (as a reader would) | Reading | Verdict |
|---|---|---|---|
| W1 | open the certificates API with no identity | `401 {"detail":"no token and no session"}` | fail-closed holds |
| W2 | sign in with the project token | `200 {"actor":"ada@example.test","role":"compliance","project_id":"prj-laya"}` | cookie issued |
| W3 | inspect the two cookies | `session`: HttpOnly **true**, value a signed blob; `csrf`: HttpOnly **false**, readable | double-submit shape holds |
| W4 | submit the claim form without the csrf header | `403 {"detail":"a session-authenticated write needs the csrf token"}` | CSRF guard holds |
| W5 | ask "share 0.66 / confidence / case" | `200 verdict=cannot_be_bounded`, reason *"the packet never measured the field 'confidence'; same-named fields are not the same quantity"* | the refusal is a result |
| W6 | ask the same share against `autorate` | `200 verdict=cannot_be_bounded`, reason *"no certificate in this packet publishes a certified autorate"* | no number laundered |
| W7 | submit an empty field | `422` | malformed claim refused |
| W8 | repeat W5 in Chinese | `200 verdict=cannot_be_bounded`, reason *"该证据包从未测量字段 'confidence'；同名字段并非同一个量"*, `locale=zh-Hans` | one catalog, both languages |
| W9 | list certificates with the session cookie | `200`, 7 summaries, first `jev / empty_feasible_set / autorate=null` | evidence read back |
| W10 | sign out, then re-open certificates | `200 {"ok":true}` then `401 {"detail":"no token and no session"}` | revocation takes effect |
| W11 | a viewer writes a claim by token, no csrf | `200 verdict=cannot_be_bounded` | token path stays csrf-exempt (V2-D1) |

**The first screen.** The served page puts `Check a claim` before `id="certificates"` in source
order, carries the line *"Three answers are possible, and cannot be bounded is a result, not a
failure"*, and the Chinese catalog renders the same sentence as
*"答案只有三种；'无法给出上界'是结论，不是故障"*. The A4 block is present in the one stylesheet:
`@page { size: A4; margin: 18mm; }`, with `.row, button, select, input, #error { display: none }`
and `break-inside: avoid` on panels and tables. These are read from the bytes the server
returned (`page.has_a4_print`, `page.claim_before_table`,
`page.claim_intro_cannot_be_failure` all `true` in the probe output).

**Three answers are possible; only one was observed.** This packet's every certificate is
`empty_feasible_set`, so the honest reply to every well-formed claim is `cannot_be_bounded`.
The probe did **not** see `bounded_supports` or `bounded_refutes` — not because it failed, but
because this corpus publishes no certified autorate to bound against. The vocabulary is fixed
in `claims.VERDICTS = ("bounded_supports", "bounded_refutes", "cannot_be_bounded")`; the two
unseen answers remain unexercised by a reader.

## 2. Why this is not the reader gate

1. **The agent cannot be confused.** It sent exactly the fields it was told to send. A human
   cannot: the point of V2-D3 is that a buyer asks "does *my* claim hold" without first
   learning the project's field names. W5/W6 are the *portal's* answer to a question an agent
   formulated, not evidence that a person would formulate that question.
2. **The agent cannot notice a lie of omission.** It checks the HTTP status and the verdict
   key. It would not notice a certificate table that quietly hid a refusal row, because it does
   not expect to see one.
3. **The visual layer was unavailable.** The browser controller opened the page and reported
   `title="autorate portal"`, but its DOM snapshot returned empty and every screenshot —
   including a 320×240 JPEG at quality 30 — exceeded the 10 MiB image limit. This is the same
   failure that interrupted the first walkthrough. Layout, legibility, focus order and the
   printed sheet were therefore **not** visually inspected; only their source-level presence
   was checked. That is a gap, not a pass.
4. **No reader signed anything.** There is no named P1/P2, no walkthrough protocol they
   followed, no notes in their words. The M4 and V2-T4 gates ask for exactly that.

**To close V2-B6:** name one P1 and one P2 outside the author, give each the same three claims,
ask them to answer "does this hold" and to file the printed sheet, and record their words and
their confusion points. This document is the script for that session, not its result.

## 3. A regression the probe run exposed and the fix

Running the full suite after re-seeding the walkthrough database found one failure that the
earlier V2 gate runs had not caught:

```
FAILED tests/test_migrations.py::test_offline_mode_renders_the_sql_before_it_runs
alembic.util.exc.CommandError: This operation cannot proceed in --sql mode; batch mode with
dialect sqlite requires a live database connection with which to reflect the table "artifact".
```

**Cause.** Migration `0005_artifact_wheel_kind.py` (added when schema-2 ingestion was fixed)
used `op.batch_alter_table("artifact")` without a `copy_from`. Batch mode must reflect the
table to rebuild it; offline `--sql` mode has no connection to reflect from. The earlier gate
ran migrations against a live database only, so the offline path was never exercised.

**Fix.** The migration now supplies an explicit reflection-free `sa.Table` mirror built from
migration 0001's exact artifact definition (`copy_from=_artifact_mirror(OLD/NEW)`). Offline
rendering now emits, without a database:

```
-- Running upgrade 0004_packet_tombstone -> 0005_artifact_wheel_kind
CONSTRAINT ck_artifact_kind CHECK (kind in ('certificate', 'document', 'records',
'protocol', 'transcript', 'wheel'))
```

**Verified after the fix:** `tests/test_migrations.py` 4/4 pass; full suite **374 passed,
1 warning** (clean `--basetemp`). Frozen repo remains clean. The only warning is the known
Starlette/httpx deprecation notice, unchanged from V2-B1.

**Fresh-database ingest (the original defect's exact path).** On a brand-new
`/tmp/fresh-migration-test.db`, `alembic upgrade head` reached `0005_artifact_wheel_kind` and the
`artifact` table's `ck_artifact_kind` reads
`kind in ('certificate', 'document', 'records', 'protocol', 'transcript', 'wheel')`. Ingesting the
real schema-2 packet `pkt-c16de007a26d9d28` (the 28 MB walkthrough bundle with two wheels)
returned `state=indexed`, `refusals=[]`, 35 artefacts of which **2 have `kind=wheel`**. The exact
failure this migration was written for — a schema-2 packet refused at the database step — does
not reproduce after the fix.

## 4. Gate rows after this pass

| Row | Reading | Verdict |
|---|---|---|
| V2-B1 | suite, after the §3 fix — `374 passed, 1 warning` | pass |
| V2-B6 | external reader walkthrough — still no P1/P2 named; only a machine probe exists | `not-run` |
| V2-B6′ | machine-agent HTTP probe — W1–W11 all as read above; source-level first-screen and A4 checks true | pass *(agent only; does not close B6)* |

## What this probe does not prove

1. **That a person can use the portal.** See §2. This is the whole point of the open gate.
2. **That the printed sheet is correct.** The A4 CSS exists in source; no sheet was visually
   rendered or filed because the visual layer failed.
3. **That the two bounded verdicts appear.** The fixture corpus cannot produce them; a packet
   with a published certified autorate is needed.
4. **That migrations work against a non-SQLite backend.** All migration verification here,
   including the fresh-database ingest, is SQLite. PostgreSQL is configured by one environment
   variable and documented, but was not started on this machine; batch rebuild DDL is
   dialect-specific and would need its own check.
