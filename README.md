# autorate-portal

Evidence packets for [autorate](https://github.com/Jackxiaozhiren/autorate). The portal tier
**computes no statistic** (PRD I1). It bundles the artefacts that `autorate` published, verifies
their bytes, renders them, and replays them with a pinned distribution so a stranger can
re-derive the same denominator without access to the producing organisation.

This repository is **M2** of the Autorate Portal plan: M1's packet contract plus the replay
engine — a job runner whose run rows carry argv, exit code and stdout hash; a pinned-distribution
registry that can contradict a forged packet; and `doctor`. M3–M5 (auth, database, HTTP API,
policies, in-browser verifier) are deliberately not implemented here.

## Install

```bash
uv sync --frozen --extra dev
uv run --frozen autorate-portal --help
```

Requires Python >= 3.10 and `pydantic>=2.6,<3`. Nothing else is needed for build / verify / html.
`verify-packet` additionally needs network access to PyPI and either Docker or `uv`.

## Command surface

| Command | Purpose |
|---|---|
| `autorate-portal packet build --source <checkout> --out <packet.tar> --revision <sha>` | Deterministic tar with an explicit, literal artefact list |
| `autorate-portal packet verify <packet.tar> [--registry registry.json]` | AC1 integrity check; optional idempotent index (AC14) |
| `autorate-portal packet html <packet.tar> -o view.html` | Self-contained HTML view, no records rows, no script |
| `autorate-portal verify-packet <packet.tar> [--backend container\|uv]` | AC9/AC10 replay of the pinned wheel |
| `autorate-portal doctor [--backend ...] [--packet P]` | What this machine can be asked to do, before a replay is spent |
| `autorate-portal run <packet.tar> [--backend ...] [--runs runs.jsonl]` | One replay job, recorded as a run row (AC4, I5) |
| `autorate-portal runs list\|show --runs runs.jsonl` | Read the recorded rows back |

Build flags: `--version`, `--wheel`, `--wheel-sha256`, `--expected-rederived`, `--shareable`.
The defaults pin `autorate==0.1.2`, wheel `autorate-0.1.2-py3-none-any.whl`, sha256
`7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205`.

### Exit codes

| rc | State | Meaning |
|---|---|---|
| 0 | `certified` / ok | Integrity verified, or replay reproduced the stored denominator |
| 2 | usage | Command-line or environment error |
| 3 | `not-run` | Replay prerequisites absent. **Never** a pass |
| 4 | `refused` / `mismatch` | Tampered bytes, a broken manifest, a pin the registry rejects, a failed replay, or a replay that disagrees with the stored summary. Nothing is certified |

A refusal prints the artefact path, the reason, and both the expected and actual sha256. An
AC10 `not-run` names which prerequisite was missing and still carries a `run` row whose `state`
is not `certified`.

### Pinned distributions

`src/autorate_portal/pins.json` is the registry: every distribution this portal has agreed to
replay, with its wheel filename and sha256. A packet pinning a version that is not registered, or
a wheel or hash that disagrees with the registry, is refused **before** anything is fetched from
PyPI — a reachable index must not be able to vouch for a forged manifest. Widening the registry is
a reviewed change, not a fallback to "latest".

### Mismatch is not a pass

`run` compares the replay's `re-derived N /M values` line with the packet's stored denominator, and
the replay's stdout hash with the manifest's hash. When they disagree the row's `state` is
`mismatch`, its reason names **both** digests, and the exit code is 4 — the code Section 3.3
already gives drift. A view renders that as a mismatch, not as a number.

## Manifest contract

`manifest.json` is the first member of the bundle. All fields are **required** — a missing field
is a validation error, never a default. `extra="forbid"` rejects claims nobody published. Fixed
spellings (PRD §13.3 item 3): `bound_unit`, `protocol_digest`, `manifest_sha256`, `packet_id`.

The contract records: protocol digest and full sha256; `source_revision` and `source_version`;
per-artefact `path`, `sha256`, `kind` and `bytes`; the pinned wheel's filename and sha256; the
lane, the rubric, the expected `re-derived N /N` line; and `records_excluded` together with the
explicit `excluded_records` list. `manifest_sha256` is the sha256 of the canonical JSON with that
field removed, so a one-character edit is detected before any artefact is read.

## Reproducibility

The tar is written with sorted names, `mtime=0`, `uid=gid=0`, empty user/group names and mode
`0644`. Two builds from the same tree are byte-identical. The artefact plan is a **literal**,
not a glob: a missing publication-table artefact is named by the build refusal.

`verify-packet` fetches the pinned wheel from PyPI, checks its sha256 **before** running anything,
installs it into an isolated location, and requires the replay to print
`re-derived N /N values` matching the manifest. It records `argv`, `exit_code`,
`stdout_sha256`, `digest_then`, `packet_id_in` and `state` in the §4.3 run-row shape. With no
Docker or no network the result is a named `not-run` (AC10), never a certified result.

## Privacy

A shareable packet excludes every `data/records_*.jsonl` artefact and **names** each exclusion in
`excluded_records` (PRD §8.4). Records rows are never embedded in the HTML view. Replay requires
the org-private packet and therefore reports `not-run` for a shareable packet.

## Tests and plants

```bash
uv run --frozen --extra dev pytest -q
uv run --frozen --extra dev python tools/plants.py
python tools/i6_plant.py <packet.tar> --backend uv
```

`tools/plants.py` runs 21 negative controls: each mutates exactly one guard, proves in a fresh
interpreter that the mutated module is what actually runs, observes the target test go red, then
restores the source with a sha256 receipt. Each child gets its own bytecode cache, because CPython
invalidates `.pyc` by `(source mtime in seconds, size)` — on a fast CI runner, several plants can
otherwise land inside the same second and silently reuse a stale cache.

The I6 plant swaps the pinned wheel hash, observes a named refusal with both hashes, and restores
the original bundle with a before/after sha256 receipt. A plant that cannot fail is not evidence.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
