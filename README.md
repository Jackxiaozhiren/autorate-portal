# autorate-portal

Evidence packets for [autorate](https://github.com/Jackxiaozhiren/autorate). The portal tier
**computes no statistic** (PRD I1). It bundles the artefacts that `autorate` published, verifies
their bytes, renders them, and replays them with a pinned distribution so a stranger can
re-derive the same denominator without access to the producing organisation.

This repository is **M1** of the Autorate Portal plan. M2–M5 (web features, auth, replay job
runner, HTTP API) are deliberately not implemented here.

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

Build flags: `--version`, `--wheel`, `--wheel-sha256`, `--expected-rederived`, `--shareable`.
The defaults pin `autorate==0.1.2`, wheel `autorate-0.1.2-py3-none-any.whl`, sha256
`7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205`.

### Exit codes

| rc | State | Meaning |
|---|---|---|
| 0 | `certified` / ok | Integrity verified, or replay reproduced the stored denominator |
| 2 | usage | Command-line or environment error |
| 3 | `not-run` | Replay prerequisites absent. **Never** a pass |
| 4 | `refused` / drift | Tampered bytes, a broken manifest, a pinned-wheel mismatch, or a failed replay. Nothing is indexed |

A refusal prints the artefact path, the reason, and both the expected and actual sha256. An
AC10 `not-run` names which prerequisite was missing and still carries a `run` row whose `state`
is not `certified`.

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
python tools/i6_plant.py <packet.tar> --backend uv
```

The I6 plant swaps the pinned wheel hash, observes a named refusal with both hashes, and restores
the original bundle with a before/after sha256 receipt. A plant that cannot fail is not evidence.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
