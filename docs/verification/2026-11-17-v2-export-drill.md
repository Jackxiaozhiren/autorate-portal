# V2 export drill — 2026-11-17

A real packet, three real bundles, and an audit done with the standard library only.

**Source packet.** `offline-v2.packet.tar`, built from `autorate` revision
`5e76fcd012ae2743b87303100d89c8f3513c35f9`, version `0.1.2`, `packet_id`
`pkt-c16de007a26d9d28`, protocol digest `ce43f8e29cc1`, stored denominator `612 /612`,
schema 2 with a two-wheel set (`autorate` + `numpy`, macOS arm64). 35 artefacts.

## 1. Three bundles, built by the CLI

The command is `autorate-portal export build <packet> --kind <kind>`, which is the same
`exports.build_bundle` the HTTP endpoint calls — not a second implementation.

| kind | lines | gaps | bundle_sha256 |
|---|---|---|---|
| `annex_iv` | 6 | 0 | `45aa344963d129eac3cfe2c0a613c372231a43c6f4e32bf70b75adc8bc391952` |
| `iso_42001` | 5 | 0 | `6f4d30d53d2166c359c350bfdf415146e262091146da946b3dde135b6b0a0df5` |
| `aap` | 5 | 0 | `edf4e433dc28275047a55bd8f0179774a79f257bf6832dfa3e0977aac4b20a4f` |

Every bundle carries the same two `known_limits` entries, read verbatim from
`protocol.json`: "exchangeability within group assumed; none of it is usable here" and
"no certificate exists, so no action is certified". They are a section, not a footnote;
`_known_limits` raises rather than emit an empty section.

## 2. Independent audit — stdlib only, no portal code

A script using only `tarfile`, `hashlib`, `json` opened the packet, hashed each artefact,
re-derived the protocol digest and the packet id, re-canonicalised each bundle payload and
re-hashed it:

```
protocol_digest derived : ce43f8e29cc1
manifest declares       : ce43f8e29cc1
annex_iv   lines=6 hash=ok packet=True digest=True
iso_42001  lines=5 hash=ok packet=True digest=True
aap        lines=5 hash=ok packet=True digest=True
lines audited: 16 | problems: none
```

All 16 lines agree three ways: the line's `sha256`, the manifest's `sha256` for that path,
and the bytes in the tar. **This is the claim F5 rule 4 makes, checked by something that
shares no code with the thing it checks.**

`export recheck` on each file returned `ok` with the same hash.

## 3. Determinism

Two builds of each kind, compared with `shasum`: byte-identical for all three. No clock, no
locale and no caller-supplied ordering enters the payload.

One correction to a test written for this drill: reformatting a bundle's JSON does **not**
break `recheck`, because the hash covers the canonical payload rather than the file's bytes.
That is the intended semantics — the file may be pretty-printed — but it means "byte-identical"
is a property of the builder, not something the hash asserts. The test now tampers with a value.

## 4. The gap path, on a packet a real producer could hand over

A second packet was built from the same artefacts with `docs/SLICES.md` removed
(`packet_id` `pkt-4f968142450eb986`, 34 artefacts) — the shape of a producer that has not
written that document yet.

`annex_iv` on it: **5 lines, 1 gap** — `accuracy_robustness: no evidence published`, no line
invented in its place, and the bundle is still emitted with its own hash
(`b87fff78891e1406498fa4e0c2f95d387db1548a4d65ad557c508cc2eb23e428`).

## 5. The blocking path (AC7)

A run store with a `certified` row followed by a `mismatch` row for `pkt-c16de007a26d9d28`:

```
BLOCKED: export blocked: a replay run recorded that the source no longer re-derives; run id: run-bbb
RC=4
```

No bundle file was written. Appending a later `certified` row lifted the block, and the
rebuilt bundle reproduced `edf4e433…` exactly — the same hash as in §1, so lifting the block
did not change the evidence, only the permission to emit it.

## What this drill does not prove

1. **No external reader has seen these bundles.** The three mappings in `exports.MAPPINGS` are
   this project's own pairing of headings to artefacts. Whether `accuracy_robustness` ↔
   `docs/SLICES.md` satisfies an actual Annex IV reviewer is unverified; the headings are our
   reading of the regulation, not a citation of a control number. An auditor's first edit would
   probably be to this table.
2. **A bundle is a source map, not a judgement.** It says "this heading is supported by these
   bytes". It does not say the bytes are adequate, current or complete. That claim belongs to
   the reader, which is why the packet, not the bundle, is the thing being certified.
3. **`known_limits` is only as good as the protocol.** Both entries are honest and both say
   nothing can be certified. A packet that published a reassuring `known_limits` array would
   export just as cleanly; the section is uncensorable, not automatically sceptical.
4. **Three kinds, not three standards.** `iso_42001` and `aap` are shaped like their names, not
   validated against the published documents.
