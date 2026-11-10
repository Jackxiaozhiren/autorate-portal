# M2 — Replay engine

Status: **opening.** Baseline is the frozen ledger's Section 5 block
(`docs/superpowers/specs/2026-10-15-autorate-certificate-platform-prd.ledger.md`,
branch `integration/f8-into-main` at `b55cb53`, `verify` rc 0 at `649 /649`,
B5 PUBLIC). This file is committed before the first M2 source edit, which is
what Section 13.5 asks for.

Repo: the portal. The frozen repo gains nothing here (NIF, Section 0.5) and its
denominator is the gate's first row.

## 1. What Section 7 asks for, verbatim

> **M2** Replay engine | job runner with argv/exit-code/stdout-hash capture,
> pinned-distribution registry, `doctor` | portal | AC4 (mismatch path)
> provable; run rows always carry argv; no endpoint computes a bound | engine is
> the only place with execution rights; if it fails, views degrade to "not run"

Section 6.1 turns two invariants `ACTIVE (M2)`:

- **I2** the triple travels with the number — "enforce at **emit** time in the
  renderer, not in a downstream test"; plant: drop `bound_unit` from a fixture
  artefact and assert the view renders "unavailable", not the number.
- **I5** replay not inference — "`run` rows carry argv plus exit code; no
  endpoint derives a bound from a summary"; plant: a unit test that a replay's
  argv contains the pinned `autorate` invocation.

## 2. What M1 already put in place, so M2 does not rebuild it

Read rather than assumed:

| Already there | Where | What M2 still owes |
|---|---|---|
| `argv`, `exit_code`, `stdout_sha256` on every replay outcome | `replay.py:50-67`, `run_row()` | persistence, and the *inner* command |
| wheel sha256 checked before anything runs | `replay.py:199-207` | a second source of truth for the pin |
| `not-run` with a reason and rc 3 | `replay.py:174-198` | `doctor` that reaches the same verdict earlier |
| renderer refuses a number without the triple; missing `bound_unit` → "unavailable" | `html.py:36-92` | structural emit contract, so the guard is one place and a plant can remove it |
| AC14 idempotent ingest of packets | `registry.py` | nothing (M2 adds runs, not packets) |

The gap M2 closes is therefore narrow and real: **a run row that survives the
process**, a **registry** that can contradict a forged packet, **`doctor`**, and
**AC4 as a named state** instead of a widened refusal.

## 3. Modules

### 3.1 `distributions.py` — pinned-distribution registry

```python
@dataclass(frozen=True)
class Pin:
    name: str        # "autorate"
    version: str     # "0.1.2"
    wheel: str       # "autorate-0.1.2-py3-none-any.whl"
    sha256: str      # 64 hex, the PyPI digest re-derived 2026-11-09
    source: str      # "https://pypi.org/pypi/autorate/0.1.2/json"

def load_registry(path: Path) -> tuple[Registry, list[Refusal]]
def resolve(registry, *, version, wheel, sha256) -> tuple[Pin | None, list[Refusal]]
```

Rules:

1. A packet whose `distribution.version` is **not registered** is refused
   before any network call: `distribution not in the pinned registry`. This is
   the refusal that survives PyPI being reachable — a forged manifest cannot
   bootstrap itself from the index.
2. A registered version whose `wheel`/`sha256` disagree with the packet is
   refused naming **both** values, the same shape AC1 uses for bytes.
3. The registry file is committed: `distributions/pins.json`. Duplicate version
   or a sha256 that is not 64 lowercase hex is a load-time refusal, not a
   warning.
4. Widening the registry to older releases is an owner decision (frozen ledger
   Section 4, open item 2), not something this milestone does quietly.

### 3.2 `engine.py` — the only place with execution rights

```python
@dataclass(frozen=True)
class RunRow:
    run_id: str          # sha256 over (packet_id, backend, argv, distribution)
    packet_id: str
    backend: str
    distribution: Pin
    argv: list[str]      # the process that ran, captured not reconstructed
    command: list[str]   # the argv handed to autorate's entry point
    exit_code: int | None
    stdout_sha256: str
    state: str           # certified | mismatch | refused | not-run
    reason: str
    digest_stored: str   # manifest_sha256 of the packet under test
    digest_replayed: str # sha256 of the replay's stdout
    denominator_stored: str
    denominator_replayed: str
```

`run(packet, backend, registry, store)`:

1. verifies the packet (`packet.verify_bundle`) — a bad bundle never reaches
   the runner;
2. resolves the pin (§3.1);
3. calls `replay.verify_packet`, which is the only code that spawns a process;
4. maps the outcome to a state (§4) and appends the row to `runs.jsonl` -
   one row per attempt. This started as "idempotent on `run_id`, the AC14
   pattern applied to runs" and that was wrong twice: AC14 is about ingesting
   the same *packet* twice, and CI showed the replay's stdout hash moves with
   the container's pip output, so an identity keyed on "the same observation"
   would have deduplicated nothing while claiming to. A monitor's re-runs are
   a series of observations, not duplicates of one;
5. returns the row. Nothing here formats or computes a statistic — the row
   carries numbers the replay printed, and `digest_replayed` is a hash.

`doctor` is *not* allowed to call `run`. `run` is the only caller of
`subprocess`, asserted by a static test over `src/autorate_portal/**` (I1's
style, applied to execution rather than arithmetic).

### 3.3 `doctor.py`

```python
@dataclass(frozen=True)
class Check:
    name: str      # python | uv | docker | pypi | registry | packet
    status: str    # ok | fail | unknown
    detail: str

def examine(*, backend: str, registry: Path, packet: Path | None) -> list[Check]
```

Exit codes: `0` when every check the requested backend needs is `ok`; `3` when
any is `fail` (the not-run semantics of AC10, reached before spending a
replay); `2` for a usage error. `doctor` never prints a verdict word from the
certificate vocabulary — no "certified", no "passed" — only check rows. Its job
is to make AC10 predictable, not to substitute for AC9.

### 3.4 `emit.py` — I2 as one structural guard

```python
class EmitRefused(Exception): ...

def statistic(value, *, denominator, rubric, packet, unit) -> str
```

Every place `html.py` renders a number goes through this function; a number
whose `denominator`, `rubric`, `packet` or `unit` is missing raises
`EmitRefused`, and the caller renders `unavailable: <component>` instead. The
guard is at emit time because that is where the number would otherwise become
text — a test that inspects the finished document is what Section 6.1 calls a
"downstream test" and is not the mechanism, only the observation.

### 3.5 CLI

```
autorate-portal doctor [--backend container|uv] [--registry P] [--packet P]
autorate-portal run --packet P [--backend ...] [--registry P] [--runs PATH]
autorate-portal runs list [--runs PATH]
autorate-portal runs show <run_id> [--runs PATH]
```

## 4. States and exit codes

| state | rc | meaning | AC |
|---|---|---|---|
| `certified` | 0 | replay ran, denominator equals the packet's stored one | AC9 |
| `mismatch` | 4 | replay ran, and disagrees with the stored summary; both digests named | **AC4** |
| `refused` | 4 | integrity, pin or replay failure — never a pass | AC1, I6 |
| `not-run` | 3 | prerequisites absent; `argv` empty, `exit_code` null | AC10 |

No new exit code is invented: Section 3.3 already says drift is reported as the
tool's exit `4`. `mismatch` and `refused` share the code and are distinguished
by `state`, which is what a view reads.

Mismatch is detected in `engine.py`, not in `replay.py`: the replay's own
refusal (`re-derived line disagrees…`) stays exactly as M1 shipped it, and the
outcome gains one additive field, `disagrees: bool`. Widening the M1 refusal
into a new state inside `replay.py` would have changed an M1 contract to make an
M2 claim true, which is the wrong direction.

## 5. Plants (Section 6.2: a rule without a plant is not implemented)

| Plant | Mutation | Test that must go red |
|---|---|---|
| `ac4-mismatch-not-certified` | `engine` maps `disagrees` to `certified` | `test_ac4_*` |
| `ac4-digests-not-named` | mismatch row drops `digest_stored` | `test_ac4_*` |
| `i2-emit-lets-missing-unit-through` | `emit.statistic` accepts an empty `unit` | `test_i2_*` |
| `i5-run-row-drops-argv` | `RunRow.argv` written as `[]` | `test_i5_*` |
| `i5-run-row-drops-command` | `command` written as `[]` | `test_i5_*` |
| `pin-unregistered-accepted` | `resolve` accepts an unregistered version | `test_pin_*` |
| `pin-mismatch-accepted` | `resolve` ignores a wheel/sha disagreement | `test_pin_*` |
| `doctor-false-ok` | `doctor` reports `ok` with docker absent | `test_doctor_*` |
| `runner-second-executor` | a new `subprocess` call outside `engine.py`/`replay.py` | `test_only_engine_executes` |

Each is added to `tools/plants.py` with the runtime-landing marker M1's harness
already uses (`4c4ff1d`), so a plant that does not actually change behaviour is
itself a failure.

## 6. Gate table for M2 (Section 13.1, counted not described)

| Gate | Command | Must be |
|---|---|---|
| Frozen-repo non-interference | `uv run --frozen autorate verify --protocol protocol.json` | rc 0, `re-derived 649 /649 values` identical to B3 |
| Published-artefact untouched | `git diff --name-only HEAD~1 -- data/ docs/` in the frozen repo | empty of `data/`; the ledger is the one counted exception |
| New-file coverage | each new guard re-run after commit with explicit paths | rc 0 |
| Corpus-absent export lane | `git archive` + `.tracked-files`, then `AUTORATE_FEISHU_ROOT=/nonexistent AUTORATE_TRACKED_FILES=… pytest` — **both** variables | 0 failed; the 2026-11-09 reading was `1227 passed, 31 skipped` / `612 /612` |
| Portal suite | `pytest -q` | 0 failures |
| Invariant plants | I2 and I5 per Section 6.1 | each observed red, reverted with a sha256 receipt |
| Parity | Section 6.3 | **N/A at M2** — needs M3's ingest; recorded, not claimed |
| Clean-machine reproducibility | fresh clone, `doctor` then AC9 | rc 0 (`doctor` exists here for the first time) |
| Leak test | Section 0.3 command | no unlabelled hits |
| Exit-code hygiene | every cited code from its own command | asserted in the harness, not in prose |

The export-lane row used to name one variable, and this plan was run literally
against it: `AUTORATE_TRACKED_FILES` alone leaves the corpus in view, so the
suite executes a different lane and reports `1255 passed, 3 skipped`
(`gate/export_pytest_corpus_present_repro.log`, rc 0). The first version of
this paragraph said `1256 passed, 7 skipped`; that was a miscount of progress
marks, not a reading. Section 8.3: corrected, not annotated.
`1227 passed, 31 skipped` reading belongs to the run where
`AUTORATE_FEISHU_ROOT=/nonexistent` removes the corpus, and it reproduces
to the test once both variables are set.
Corrected here rather than annotated below the table, per Section 8.3.

## 7. Out of scope, named so silence is not read as done

No database, no HTTP API, no auth (M3). No policies, monitor or in-browser
verifier (M5). No change to the frozen repo beyond the ledger. No coverage floor
is invented for the portal — the absent floor from M1 (D6) is still absent and
still registered.

## 8. Stop point

Section 13.5: stop for the owner's approval at the Section 13.1 gate table
above. Nothing in this plan is a reading; the readings arrive with the gate.
