"""Negative-control plant harness (PRD section 6.1, 6.2; section 13.1 gate).

A guard that cannot fail is not evidence. For each plant this harness:

1. asserts the exact source fragment is present once (so a rename cannot make
   the plant silently inert),
2. mutates that one fragment,
3. runs the single test that must go red and records its real exit code,
4. restores the original bytes and verifies the sha256 receipt.

No skip, xfail, ignore or exemption is added at any point. Run from the repo
root with the dev environment installed:

    .venv/bin/python tools/plants.py
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "autorate_portal"


@dataclass(frozen=True)
class Plant:
    name: str
    filename: str
    old: str
    new: str
    test: str


PLANTS: tuple[Plant, ...] = (
    Plant("manifest-self-hash", "manifest.py",
          "        if computed != self.manifest_sha256:",
          "        if False and computed != self.manifest_sha256:",
          "tests/test_manifest.py::test_self_hash_mismatch_is_refused"),
    Plant("manifest-extra-forbid", "manifest.py",
          'class Manifest(BaseModel):\n    model_config = ConfigDict(extra="forbid")',
          'class Manifest(BaseModel):\n    model_config = ConfigDict(extra="allow")',
          "tests/test_manifest.py::test_extra_fields_are_refused"),
    Plant("manifest-sorted-artefacts", "manifest.py",
          "        if paths != sorted(paths):",
          "        if False and paths != sorted(paths):",
          "tests/test_manifest.py::test_duplicate_and_unsorted_artefact_paths_are_refused"),
    Plant("manifest-digest-prefix", "manifest.py",
          "        if self.protocol_sha256[:12] != self.protocol_digest:",
          "        if False and self.protocol_sha256[:12] != self.protocol_digest:",
          "tests/test_manifest.py::test_protocol_digest_is_the_declared_prefix"),
    Plant("manifest-shareable-records", "manifest.py",
          '        if self.records_excluded and any(a.kind == "records" for a in self.artifacts):',
          '        if False and self.records_excluded and any(a.kind == "records" for a in self.artifacts):',
          "tests/test_manifest.py::test_shareable_packet_cannot_declare_records_artefacts"),
    Plant("packet-tamper-hash", "packet.py",
          "        if actual != artefact.sha256:",
          "        if False and actual != artefact.sha256:",
          "tests/test_packet.py::test_tampered_byte_is_a_named_refusal_with_both_hashes"),
    Plant("packet-undeclared-file", "packet.py",
          "        if name not in declared:",
          "        if False and name not in declared:",
          "tests/test_packet.py::test_undeclared_file_is_refused"),
    Plant("packet-path-traversal", "packet.py",
          '                if (name.startswith("/") or "\\\\" in name',
          '                if False and (name.startswith("/") or "\\\\" in name',
          "tests/test_packet.py::test_path_traversal_in_bundle_is_refused"),
    Plant("packet-missing-artefact", "packet.py",
          "        if not candidate.is_file():",
          "        if False and not candidate.is_file():",
          "tests/test_packet.py::test_missing_declared_artefact_is_named"),
    Plant("packet-fixed-mtime", "packet.py",
          "            info.mtime = 0",
          "            info.mtime = 1",
          "tests/test_packet.py::test_bundle_names_are_sorted_relative_and_manifest_first"),
    Plant("packet-shareable-exclusion", "packet.py",
          '        if shareable and kind == "records":',
          '        if False and shareable and kind == "records":',
          "tests/test_packet.py::test_shareable_excludes_records_and_names_them"),
    Plant("packet-refused-hides-manifest", "packet.py",
          "    return Verification(not refusals, manifest=None if refusals else manifest,",
          "    return Verification(not refusals, manifest=manifest,",
          "tests/test_packet.py::test_tampered_byte_is_a_named_refusal_with_both_hashes"),
    Plant("registry-idempotence", "registry.py",
          "    if key in packets:",
          "    if False and key in packets:",
          "tests/test_packet.py::test_ac14_reingest_yields_one_row_and_no_duplicate_artefacts"),
    Plant("html-triple-completeness", "html.py",
          '    if missing:\n        return False, "", ", ".join(sorted(missing))',
          '    if False and missing:\n        return False, "", ", ".join(sorted(missing))',
          "tests/test_html.py::test_missing_bound_unit_renders_unavailable_not_a_number"),
    Plant("html-refusal-not-zero", "html.py",
          '        state = "NOT_CERTIFIABLE" if reason else "NOT_INFORMATIVE"',
          '        state = "0"',
          "tests/test_html.py::test_refusal_renders_verbatim_and_never_as_zero"),
    Plant("html-exclusion-disclosure", "html.py",
          "records artefacts are excluded and named ",
          "records artefacts were dropped and named ",
          "tests/test_html.py::test_never_embeds_records_rows_and_states_exclusion"),
    Plant("replay-pinned-wheel-hash", "replay.py",
          "    if actual != manifest.distribution.sha256:",
          "    if False and actual != manifest.distribution.sha256:",
          "tests/test_replay.py::test_i6_swapped_wheel_hash_is_refused_with_both_hashes"),
    Plant("replay-not-run-never-a-pass", "replay.py",
          '        return ReplayOutcome("not-run", EXIT_NOT_RUN,\n'
          '                             "replay prerequisites absent: %s" % "; ".join(reasons), **base)',
          '        return ReplayOutcome("certified", EXIT_OK,\n'
          '                             "replay prerequisites absent: %s" % "; ".join(reasons), **base)',
          "tests/test_replay.py::test_ac10_no_docker_no_network_is_a_named_not_run"),
    Plant("replay-denominator-parity", "replay.py",
          "    if rederived != manifest.expected_rederived:",
          "    if False and rederived != manifest.expected_rederived:",
          "tests/test_replay.py::test_rederived_disagreement_is_refused"),
    Plant("replay-failed-run-not-a-pass", "replay.py",
          "    if exit_code != 0:",
          "    if False and exit_code != 0:",
          "tests/test_replay.py::test_failed_replay_is_never_reported_as_a_pass"),
    Plant("replay-requires-rederived-line", "replay.py",
          "    if not rederived:",
          "    if False and not rederived:",
          "tests/test_replay.py::test_replay_without_a_rederived_line_is_refused"),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_test(nodeid: str) -> int:
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", nodeid],
                          cwd=ROOT, capture_output=True, text=True, timeout=180)
    return proc.returncode


def main() -> int:
    py = sys.executable
    print("PLANT HARNESS python=%s plants=%d" % (py, len(PLANTS)))
    before_all = {p: (SRC / p).read_bytes() for p in sorted({x.filename for x in PLANTS})}
    receipts = {p: digest(data) for p, data in before_all.items()}

    fired = 0
    restored = 0
    for plant in PLANTS:
        path = SRC / plant.filename
        original = before_all[plant.filename]
        count = original.decode("utf-8").count(plant.old)
        if count != 1:
            print("PLANT %-36s INERT (fragment count=%d)" % (plant.name, count))
            continue
        mutated = original.decode("utf-8").replace(plant.old, plant.new, 1).encode("utf-8")
        landed = mutated != original
        path.write_bytes(mutated)
        try:
            rc = run_test(plant.test)
        finally:
            path.write_bytes(original)
        after = path.read_bytes()
        ok_restore = digest(after) == receipts[plant.filename]
        red = landed and rc != 0
        fired += int(red)
        restored += int(ok_restore)
        print("PLANT %-36s landed=%s test_rc=%-3s RED=%-5s RESTORED=%s"
              % (plant.name, landed, rc, red, ok_restore))

    print("PLANT SUMMARY total=%d red=%d restored=%d" % (len(PLANTS), fired, restored))
    verdict = fired == len(PLANTS) and restored == len(PLANTS)
    print("PLANT VERDICT: %s" % ("ALL RED, ALL RESTORED" if verdict else "FAILED"))
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
