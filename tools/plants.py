"""Negative-control plant harness (PRD section 6.1, 6.2; section 13.1 gate).

A guard that cannot fail is not evidence. For each plant this harness:

1. asserts the exact source fragment is present once (so a rename cannot make
   the plant silently inert),
2. mutates that one fragment AND appends a runtime-visible marker,
3. proves in a fresh child interpreter that the mutated module is what actually
   executes (section 6.2: prove the removal landed, not just that bytes changed),
4. runs the single test that must go red and records its real exit code,
5. restores the original bytes and verifies the sha256 receipt.

Each child gets its own ``PYTHONPYCACHEPREFIX`` and ``PYTHONDONTWRITEBYTECODE``.
This matters: CPython invalidates a .pyc by (source mtime in *seconds*, size).
On a fast CI runner several plants can land inside one second with equal file
sizes, so a stale .pyc from the previous plant would otherwise be reused and
the current plant would look red without ever having landed. A plant that is
not observed at runtime is reported as INERT and fails the harness.

No skip, xfail, ignore or exemption is added at any point. Run from the repo
root with the dev environment installed:

    .venv/bin/python tools/plants.py
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "autorate_portal"
MARKER = "\n_PLANT_LANDED_MARKER = %r\n"
PROBE = (
    "import importlib, sys; "
    "m = importlib.import_module('autorate_portal.%s'); "
    "assert getattr(m, '_PLANT_LANDED_MARKER', None) == sys.argv[1], "
    "'mutated module is not what executed'; "
    "print('RUNTIME_LANDED')"
)


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
    Plant("emit-triple-completeness", "emit.py",
          "    missing = missing_components(values)\n"
          "    if missing:\n"
          "        raise EmitRefused(missing)",
          "    missing = missing_components(values)\n"
          "    if False and missing:\n"
          "        raise EmitRefused(missing)",
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
    # --- M2: the replay engine, its registry, doctor, and the run row ---
    Plant("ac4-mismatch-not-certified", "engine.py",
          "    if outcome.disagrees:\n        return \"mismatch\"",
          "    if False and outcome.disagrees:\n        return \"mismatch\"",
          "tests/test_engine.py::test_ac4_a_mismatch_names_both_digests_and_is_never_certified"),
    Plant("ac4-mismatch-reason-drops-digests", "engine.py",
          '        reason = ("stored denominator %s disagrees with the replay\'s %s; "\n'
          '                  "stored digest %s, replay digest %s"\n'
          "                  % (manifest.expected_rederived, outcome.rederived,\n"
          "                     manifest.manifest_sha256, outcome.stdout_sha256))",
          '        reason = ("stored denominator %s disagrees with the replay\'s %s"\n'
          "                  % (manifest.expected_rederived, outcome.rederived))",
          "tests/test_engine.py::test_ac4_a_mismatch_names_both_digests_and_is_never_certified"),
    Plant("i5-run-row-drops-argv", "engine.py",
          "argv=list(argv), command=list(command),",
          "argv=[], command=list(command),",
          "tests/test_engine.py::"
          "test_i5_a_certified_run_row_carries_the_pinned_invocation_and_exit_code"),
    Plant("i5-run-row-drops-command", "engine.py",
          "argv=list(argv), command=list(command),",
          "argv=list(argv), command=[],",
          "tests/test_engine.py::"
          "test_i5_a_certified_run_row_carries_the_pinned_invocation_and_exit_code"),
    Plant("pin-unregistered-accepted", "distributions.py",
          "    if pin is None:\n        return None, [Refusal(",
          "    if pin is None:\n"
          "        pin = Pin(name=name, version=version, wheel=wheel, sha256=sha256, source=\"\")\n"
          "    if False:\n        return None, [Refusal(",
          "tests/test_distributions.py::test_an_unregistered_version_is_refused_and_names_what_is_registered"),
    Plant("pin-sha-mismatch-accepted", "distributions.py",
          "    if pin.sha256 != sha256:",
          "    if False and pin.sha256 != sha256:",
          "tests/test_distributions.py::test_a_sha256_disagreement_names_both_sides"),
    Plant("pin-wheel-mismatch-accepted", "distributions.py",
          "    if pin.wheel != wheel:",
          "    if False and pin.wheel != wheel:",
          "tests/test_distributions.py::test_a_wheel_filename_disagreement_names_both_sides"),
    Plant("doctor-docker-false-ok", "doctor.py",
          '    return Check("docker", "ok" if env.docker_available else "fail", env.docker_detail)',
          '    return Check("docker", "ok", env.docker_detail)',
          "tests/test_doctor.py::test_missing_docker_fails_the_container_backend_and_exits_not_run"),
    Plant("doctor-container-network-false-ok", "doctor.py",
          '    reachable, detail = probe(image)\n'
          '    return Check("container-network", "ok" if reachable else "fail", detail)',
          '    reachable, detail = probe(image)\n'
          '    return Check("container-network", "ok", detail)',
          "tests/test_doctor.py::test_container_without_egress_is_a_failing_check"),
    Plant("engine-second-executor", "engine.py",
          "import json\nfrom dataclasses import dataclass, field",
          "import json\nimport subprocess  # a second executor must be caught by the static rule\n"
          "from dataclasses import dataclass, field",
          "tests/test_only_engine_executes.py::test_only_one_module_can_spawn_a_process"),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def child_env(cache: Path) -> dict[str, str]:
    """Force every child to import the current working tree, with no stale .pyc."""
    existing = os.environ.get("PYTHONPATH", "")
    pythonpath = str(ROOT / "src") + (os.pathsep + existing if existing else "")
    return {**os.environ,
            "PYTHONPATH": pythonpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": str(cache)}


def probe_module(plant: Plant, env: dict[str, str]) -> bool:
    module = plant.filename[:-3]
    proc = subprocess.run([sys.executable, "-B", "-c", PROBE % module, plant.name],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        print("  PROBE FAILED: %s" % (proc.stdout + proc.stderr).strip()[:300])
    return proc.returncode == 0


def run_test(nodeid: str, env: dict[str, str]) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, "-B", "-m", "pytest", "-q", nodeid],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
    return proc.returncode, (proc.stdout + proc.stderr)[-600:]


def clear_bytecode() -> None:
    for directory in (ROOT / "src", ROOT / "tests", ROOT / "tools"):
        for cache in directory.rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)


def main() -> int:
    print("PLANT HARNESS python=%s plants=%d" % (sys.executable, len(PLANTS)))
    clear_bytecode()
    before_all = {p: (SRC / p).read_bytes() for p in sorted({x.filename for x in PLANTS})}
    receipts = {p: digest(data) for p, data in before_all.items()}

    fired = 0
    landed_runtime = 0
    restored = 0
    for plant in PLANTS:
        path = SRC / plant.filename
        original = before_all[plant.filename]
        text = original.decode("utf-8")
        count = text.count(plant.old)
        if count != 1:
            print("PLANT %-36s INERT (fragment count=%d)" % (plant.name, count))
            continue
        mutated = (text.replace(plant.old, plant.new, 1)
                   + (MARKER % plant.name)).encode("utf-8")
        landed = mutated != original
        path.write_bytes(mutated)
        try:
            with tempfile.TemporaryDirectory(prefix="plant-pyc-") as cache:
                env = child_env(Path(cache))
                probe_ok = probe_module(plant, env)
                rc, tail = run_test(plant.test, env)
        finally:
            path.write_bytes(original)
        after = path.read_bytes()
        ok_restore = digest(after) == receipts[plant.filename]
        red = landed and probe_ok and rc != 0
        fired += int(red)
        landed_runtime += int(probe_ok)
        restored += int(ok_restore)
        print("PLANT %-36s landed=%s runtime=%s test_rc=%-3s RED=%-5s RESTORED=%s"
              % (plant.name, landed, probe_ok, rc, red, ok_restore))
        if not red:
            print("  TEST OUTPUT TAIL: %s" % tail.replace("\n", " | ")[-400:])

    clear_bytecode()
    leftover = [p.name for p in SRC.glob("*.py") if "_PLANT_LANDED_MARKER" in p.read_text()]
    print("PLANT SUMMARY total=%d runtime_landed=%d red=%d restored=%d leftover_markers=%s"
          % (len(PLANTS), landed_runtime, fired, restored, leftover))
    verdict = (fired == len(PLANTS) and landed_runtime == len(PLANTS)
               and restored == len(PLANTS) and not leftover)
    print("PLANT VERDICT: %s" % ("ALL RED, ALL RESTORED" if verdict else "FAILED"))
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
