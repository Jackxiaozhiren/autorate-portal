# M1 Evidence Packet — implementation plan (2026-11-09)

Status: **plan only, no source edits**. Prepared in the M1 opening session. PRD §7 requires one
plan per milestone with tasks at test-cycle size; this is that plan. It is held outside the frozen
repo until the owner decides where the `autorate-portal` repository lives (see Blocker B1).

## 1. Definition of done (PRD §7, M1 row)

| Item | Source |
|---|---|
| Manifest contract as a Pydantic model | §7 M1, §4.2 |
| `autorate-portal packet build \| verify \| html` | §7 M1 |
| One packet built from the frozen repo's **committed** artefacts | §7 M1 |
| `verify-packet` replay in a clean container | §7 M1, I6 |
| AC1, AC9, AC10, AC14 pass | §5.11 |
| I6 plant fires red, then restores with a hash receipt | §6.1, §6.2 |
| Packet builds reproducibly from a clean checkout of the pinned revision | §7 M1 |
| Frozen repo untouched (NIF) | §0.5, §7 sequencing rules |

Explicitly **out of scope**: F1–F10 web features, auth/roles, the replay job runner (M2), the
portal HTTP API (M3), any `--format json` change to `autorate` (M5, freeze round only).

## 2. Baseline (captured 2026-11-09, see `../m0-f8-2026-11-06/logs/m1_baseline_2026-11-09.log`)

| B | Reading | Exit |
|---|---|---|
| B1 | branch `integration/f8-into-main`, tip `e9b0cf1` (same commit as `origin/main`) | 0 / 0 |
| B2 | `git status --short` empty (0 lines) | 0 |
| B3 | `autorate verify --protocol protocol.json` → corpus present, `re-derived 649 /649 values`, protocol `ce43f8e29cc1` (frozen 2026-10-17) | 0 |
| B4 | `autorate --help` → 10 subcommands (`snapshot … verify`) | 0 |
| B5 | `gh repo view --json visibility,stargazerCount` → `{"stargazerCount":1,"visibility":"PUBLIC"}` | 0 |

Hard rule §0.4 satisfied: B3 exits 0, so M1 may start. Denominators for NIF comparison: **649 /649**.

## 3. Blockers that require an owner decision

- **B1 (blocking).** PRD §7 puts M1 in the `portal` repo; §12.3 A3 fixes the name
  `autorate-portal` / import package `autorate_portal`. Neither a local directory under the
  workspace nor a GitHub repository with that name exists (checked 2026-11-09). §13.5 says
  "Do not carry the previous session's approval forward" and §0.2 carve-outs (a) and (b) still
  apply. Creating a **public** GitHub repository is an external action, so it waits for an
  explicit instruction. A local-only scaffold is possible without that instruction but would
  leave M1 without the CI that I6's plant requires.
- **B2 (not blocking).** `verify-packet` needs a pinned, resolvable distribution. PyPI carries
  `autorate 0.1.0` and, after this session's release, `0.1.2`. Pin the wheel by SHA-256 in the
  packet manifest, never by a floating version.
- **B3 (not blocking).** Docker 29.8.2 is installed; `podman` is absent. AC10's "no Docker, no
  network" path must be simulated by an injected environment guard, not by uninstalling Docker.

## 4. Proposed layout in the portal repo

```
pyproject.toml                       # name autorate-portal, console script autorate-portal
src/autorate_portal/
    __init__.py
    cli.py                           # packet build|verify|html, verify-packet
    manifest.py                      # Pydantic contract: manifest.json
    packet.py                        # bundler: hash, byte-for-byte write, deterministic order
    replay.py                        # container/uv replay, argv + exit code + stdout hash
    html.py                          # self-contained viewer, no records rows
tests/
    test_manifest.py  test_packet.py  test_replay.py  test_html.py  test_cli.py
    plants/test_i6_wheel_hash.py
docs/superpowers/plans/2026-11-09-m1-evidence-packet.md   # this plan, once the repo exists
```

Type spellings are fixed by §13.3 item 3: `bound_unit`, `protocol_digest`, `manifest_sha256`,
`packet_id`. No new spellings.

## 5. Tasks at test-cycle size (red → green, one task = one test cycle)

1. **T1 manifest schema.** Write a failing test for `manifest.json` requiring `protocol_digest`,
   `manifest_sha256`, per-artefact `path`/`sha256`/`kind`, pinned wheel hash and `source_revision`.
   Then implement the Pydantic model. A missing field must be a validation error, never a default.
2. **T2 build.** Failing test: build a packet from a fixture tree and assert deterministic bytes
   (double-build byte compare, §11 Reproducibility), sorted paths, no absolute paths, no records
   rows in the shareable variant (§8.4). Implement `packet build`.
3. **T3 verify / AC1.** Failing test: flip one artefact byte → refuse, name the path, print both
   hashes, index nothing (`rc 4` analogue). Then implement `packet verify`.
4. **T4 html.** Failing test: the viewer renders every number with its triple
   (denominator, budget/rubric, packet id + protocol digest) and renders a refusal as refusal text
   (I2, I3, R1). No computation in the renderer (I1).
5. **T5 idempotence / AC14.** Failing test: ingesting the same `manifest_sha256` twice yields one
   row and no duplicate artefacts.
6. **T6 replay / AC9.** Failing test: in a clean container with PyPI access and no repo access,
   `verify-packet` exits 0 and prints `re-derived N /N` matching the packet's stored N. Pin the
   wheel hash; capture argv, exit code and stdout hash into the `run` row shape (§4.3).
7. **T7 AC10.** Failing test: absent Docker and absent network → `not-run` with the reason, never
   a pass. Inject the environment; do not weaken the check.
8. **T8 I6 plant.** Swap the pinned wheel hash in CI, expect `rc != 0`, revert with a hash receipt.
   A plant that cannot fail is not evidence (§6.2).
9. **T9 frozen-repo packet.** Build one packet from `e9b0cf1`'s committed artefacts:
   `protocol.json`, `docs/RESULTS.md`, `docs/AUDIT.md`, `docs/SLICES.md`, the seven
   `data/cert_*.json` certificates and `data/inventory.md(.json)`. Exclude `data/*.jsonl`
   (§8.4: never ship records rows in a shareable bundle).
10. **T10 reproducibility from a clean checkout.** `git clone` the pinned revision into a fresh
    container, rebuild, byte-compare the packet.

## 6. Gate mapping (PRD §13.1) — to be run at the stop point

| Gate | M1 evidence |
|---|---|
| Frozen-repo non-interference | `autorate verify` rc 0, `re-derived 649 /649 values`, identical to B3 |
| Published-artefact untouched | `git diff --name-only HEAD~1 -- data/ docs/` empty in the frozen repo |
| New-file coverage | portal guards re-run after commit with explicit paths |
| Corpus-absent export lane | frozen repo lane if any tracked file is added there (none is planned) |
| Portal suite | `uv run --frozen pytest -q` in the portal repo, 0 failures |
| Invariant plants | I6 plant observed red, reverted with a hash receipt; I1–I5 recorded `UNPROVEN` in M1 |
| Parity | §6.3 job is M3's gate; record as not applicable to M1 rather than claiming green |
| Clean-machine reproducibility | T10 plus AC9 in a clean container |
| Leak test | §0.3 command; adjudicate lawful hits out loud (see the opening report) |
| Exit-code hygiene | each cited exit code from its own command with `echo "NAME_EXIT=$?"` |

## 7. Deviations to register, not to hide

- §13.5 says "ledger commit before source edits" and names the frozen repo's ledger. M1's source
  edits belong to the portal repo; the ledger commit therefore records the baseline reading in the
  frozen repo, and the portal repo carries its own gates. Any `docs/` change in the frozen repo is
  a deviation from the §13.1 "published-artefact untouched" gate and must be counted, not
  described as zero.
- §8.1's order (`PyPI release -> tag -> portal M1-M4`) is satisfied: M1 starts only after the
  `autorate 0.1.2` release and its tag.
