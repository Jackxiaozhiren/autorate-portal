# V2 monitor series drill — 2026-11-17

Four observations of one packet, three of them started and one stopped before it began, read
back as two series. Every verdict below comes from a real replay or a real refusal; no exit
code was injected.

**Packet.** `pkt-c16de007a26d9d28` (schema 2, `612 /612` stored) and a second packet built
from the same bytes with the stored denominator set to `590 /612` to produce a genuine
disagreement. Both share the id, for the reason in §4.

## 1. The observations

`monitor.observe` against a real SQLite database, the same call the HTTP endpoint makes.

| # | how it was produced | verdict | rc | the tool's words |
|---|---|---|---|---|
| A1 | registry file is not JSON | `not_run` | 3 | `pinned-distribution registry unusable: … distribution r…` |
| A2 | registry pins a wrong wheel sha256 | `refused` | 4 | `packet pin rejected by the registry: … wheel sha256 disagrees` |
| A3 | correct packet, real uv replay, index made unreachable | `holds` | 0 | `replay reproduced the packet's stored denominator` |
| B1 | packet storing `590 /612`, real uv replay | `drift` | 4 | `stored denominator 590 /612 disagrees with the replay's 612 /612` |

Series A reads back as `not_run → refused → holds` with exit codes `null, null, 0`; series B
is the single `drift`. `results_for` orders by `started_at`, so the red one stays first even
after a later green — the series is chronological, not sorted by severity.

## 2. The drill found a wrong verdict, which no unit test could have

Before this drill, a genuine disagreement was reported as **`holds`**.

The reason is structural: the portal compares the re-derived denominator with the stored one,
so a replay that disagrees has still succeeded **as a process** and exits `0`. `verdict_for`
read the exit code first, saw `0`, and returned `holds` — while the run row said
`state=mismatch`. The drift was real, recorded, and reported as the opposite of itself.

Every existing monitor test passed, because every one of them injected the *tool's* exit 4
(`_env(rc=4, …)`). The tool never produces that code for this comparison; the portal does, in
a different field.

The fix reads state before code, now for two states:

* `mismatch` → `drift`, whatever the exit code says;
* `not-run` → `not_run`; `refused` with no exit code or with the install sentinel `97` →
  `refused` (nothing was observed, so nothing drifted).

A regression test (`test_a_disagreement_that_exited_zero_is_still_drift`) now pins the case
that the drill found.

## 3. Exit-code collisions, stated rather than hidden

| verdict | rc | collides with |
|---|---|---|
| `holds` | 0 | — |
| `configuration_bug` | 2 | — |
| `not_certifiable` | 3 | `not_run` (both 3) |
| `drift` | 4 | `refused` (both 4) |

A scheduler that keys on the exit code alone cannot separate these pairs. One that reads the
printed verdict line, or the run row's `state`, can. Narrowing the collisions would mean
renumbering the tool's exit codes, which is a protocol change and is not in V2.

## 4. Two packets, one id — deliberate, and its cost

The `590 /612` packet and the `612 /612` packet share `pkt-c16de007a26d9d28`, because the id
covers the protocol digest, the source revision, the artefact hashes and `shareable` — not
`expected_rederived` and not the pinned wheel. That exclusion is load-bearing: if the id moved
when the stored denominator moved, a one-field manifest edit would launder a recorded mismatch
by giving it a fresh identity. AC7 would be bypassable with a text editor.

The cost is over-blocking, and it is real: series B's `mismatch` is the **deciding row** for
`pkt-c16de007a26d9d28`, so an export of the `612 /612` packet is blocked by a drift observed on
the `590 /612` packet until a `certified` row for that id supersedes it. Fail-closed, at the
price of one extra replay.

## 5. Scheduler contract

The portal owns no clock. A scheduler calls the same command a human would:

```
17 3 * * *  cd /srv/autorate && autorate-portal monitor packet.tar \
              --backend container --runs /var/lib/autorate/runs.jsonl >> /var/log/autorate.log 2>&1
```

Exit codes: `0` holds, `3` not certifiable **or** not run, `4` drift **or** refused, `2`
configuration bug. The first line of stdout is `verdict : <name> (<display term>)`; that name
is the thing to alert on, and it is never inferred from the code.

| verdict | what an operator should do |
|---|---|
| `holds` | nothing |
| `not_certifiable` | nothing; the source is answering, the answer is "not certifiable" |
| `drift` | read the quoted summary line, then re-run once by hand before paging anyone |
| `refused` | fix the host or the packet: a pin, an integrity check, a wheel set for this platform |
| `not_run` | fix the host: the question was never asked. Never a green |
| `configuration_bug` | fix the invocation |
| `failed` | the tool exited outside its documented vocabulary; treat as a contract violation |

## What this drill does not prove

1. **A scheduler has not actually called it.** The command was run by hand, four times. No
   cron entry exists on this machine; the contract above is a specification, not an observation.
2. **`not_certifiable` is not exercised here.** Every run in this drill either re-derived or
   failed to start; producing a real `3` needs a packet whose source genuinely cannot be
   bounded, which the real corpus does not yield.
3. **The series is per project, not per packet.** `results_for` scopes by `project_id` and
   joins by run id; two packets in one project produce one interleaved series ordered by time.
   That is fine for a single monitored packet and ambiguous for two.
