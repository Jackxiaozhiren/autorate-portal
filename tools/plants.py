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
import re
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
    "m = importlib.import_module(sys.argv[2]); "
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
    Plant("i1-summary-computes-a-bound", "db.py",
          "    unknown = sorted(set(fields) - set(SUMMARY_FIELDS))",
          "    fields = {**fields, \"bound\": str(sum(float(v) for v in fields.values() "
          "if isinstance(v, str) and v.replace('.', '', 1).isdigit()) or 0)}\n"
          "    unknown = sorted(set(fields) - set(SUMMARY_FIELDS))",
          "tests/test_db.py::test_no_module_in_the_package_computes_an_aggregate"),
    Plant("i3-refusal-renders-a-zero", "views.py",
          "        return Panel(title, REFUSAL, reason, '<p class=\"reason\">%s</p>' % e(reason))",
          "        return Panel(title, REFUSAL, reason, '<p class=\"reason\">%s</p><p>0</p>' % e(reason))",
          "tests/test_views_f2.py::test_ac2_a_refusal_prints_the_reason_verbatim_and_no_number_at_all"),
    Plant("i2-bound-unit-dropped", "emit.py",
          '        "bound_unit": None if _absent(bound_unit) else str(bound_unit),',
          '        "bound_unit": None,',
          "tests/test_views_f2.py::test_ac3_a_number_carries_denominator_budget_packet_and_unit_in_one_component"),
    Plant("f1-tampered-bytes-accepted", "packet.py",
          "        if actual != artefact.sha256:",
          "        if False and actual != artefact.sha256:",
          "tests/test_ingest.py::test_one_tampered_byte_is_a_named_refusal_and_nothing_is_indexed"),
    Plant("f3-truncation-silent", "views.py",
          "    return ordered[:cap], len(rows) - cap",
          "    return ordered[:cap], 0",
          "tests/test_views_f3.py::test_an_over_cap_slice_list_keeps_the_smallest_ns_and_counts_the_rest"),
    Plant("ac13-viewer-reads-records", "app.py",
          '        if artifact.kind != "protocol":',
          '        if False and artifact.kind != "protocol":',
          "tests/test_api.py::test_ac13_a_viewer_reading_records_is_refused_and_named_in_the_audit"),
    Plant("parity-absent-fixtures-not-named", "tools/parity.py",
          "    return [name for name in ALL_ARTEFACTS if not (frozen / name).is_file()]",
          "    return []",
          "tests/test_parity.py::test_an_absent_fixture_is_named_and_the_run_fails"),
    Plant("f3-per-group-shape-ignored", "views.py",
          '    per_group = run.get("per_group") or {}',
          "    per_group = {}",
          "tests/test_views_f3.py::test_a_published_slices_artefact_is_read_from_run_per_group"),
    Plant("f3-a-refused-group-renders-a-label", "views.py",
          '    if row.get("feasible") is False:',
          "    if False and row.get(\"feasible\") is False:",
          "tests/test_views_f3.py::test_a_group_that_refuses_carries_its_reason_and_no_number"),

    # M4 plants. I4 is the invariant turning ACTIVE in this milestone, so its
    # Section 6.2 plant ("seed two packets at different digests and open a
    # trend") is here rather than described in prose. Each of the others
    # removes one guard that an M4 surface relies on.
    Plant("m4-i4-cross-freeze-trend-drawn", "trend.py",
          "    if len(digests) > 1 and not boundary:",
          "    if False and len(digests) > 1 and not boundary:",
          "tests/test_trend.py::test_ac8_two_freezes_do_not_share_an_axis_without_a_boundary"),
    Plant("m4-f4-unmeasured-field-accepted", "claims.py",
          "    if claim.field not in declared:",
          "    if False and claim.field not in declared:",
          "tests/test_claims_audit.py::test_ac6_a_field_the_packet_never_measured_is_cannot_be_bounded_with_comparability"),
    Plant("m4-f4-refutes-comparison-disabled", "claims.py",
          "    if share > published:",
          "    if False and share > published:",
          "tests/test_claims.py::test_ac5_a_share_above_the_certified_autorate_refutes_with_both_numbers_and_units"),
    Plant("m4-f5-known-limits-omitted", "exports.py",
          "    if not isinstance(limits, list) or not limits or not all(isinstance(x, str) for x in limits):",
          "    if False and (not isinstance(limits, list) or not limits or not all(isinstance(x, str) for x in limits)):",
          "tests/test_exports.py::test_known_limits_is_its_own_section_and_cannot_be_omitted"),
    Plant("m4-f5-source-less-line-accepted", "exports.py",
          "    if missing:\n        raise ExportRefused",
          "    if False and missing:\n        raise ExportRefused",
          "tests/test_exports.py::test_a_line_without_a_source_fails_the_build_of_the_bundle"),
    Plant("m4-ac7-stale-source-exported", "exports.py",
          "        if actual != artefact.sha256:",
          "        if False and actual != artefact.sha256:",
          "tests/test_exports.py::test_ac7_a_source_that_no_longer_rederives_blocks_the_export"),
    Plant("m4-ac7-replay-mismatch-swallowed", "exports.py",
          "    if replay:\n        return Bundle",
          "    if False and replay:\n        return Bundle",
          "tests/test_api_claims_exports.py::test_ac7_over_http_a_replay_mismatch_blocks_the_export_with_its_run_id"),
    Plant("m4-badge-privacy-flag-flipped", "badge.py",
          '        "records_included": False,',
          '        "records_included": True,',
          "tests/test_badge.py::test_the_shareable_badge_carries_the_published_triple_and_no_records"),
    Plant("m4-i18n-unit-translation-dropped", "i18n.py",
          "    if key in table:\n        return table[key], True",
          "    if False and key in table:\n        return table[key], True",
          "tests/test_i18n.py::test_unit_words_are_translated_and_an_unknown_unit_is_not_guessed"),
    Plant("m4-ac11-staleness-swallowed", "policies.py",
          "    state = STALE if newer else ACTIVE",
          "    state = ACTIVE if newer else ACTIVE",
          "tests/test_policies.py::test_ac11_a_superseded_packet_is_stale_in_the_sdk_payload"),
)


def resolve(filename: str) -> Path:
    """A plant names its file relative to the package, or to the repo root.

    Most plants mutate the package; the parity tool lives in ``tools/`` and is
    the one control whose subject is outside ``src/``. Resolving rather than
    guessing keeps a typo from silently pointing at a file that is not there.
    """
    package = SRC / filename
    return package if package.is_file() else ROOT / filename


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def child_env(cache: Path) -> dict[str, str]:
    """Force every child to import the current working tree, with no stale .pyc.

    Each plant also gets its own TMPDIR. This sandbox's mkdir shim ignores
    ``exist_ok`` on a directory that already exists, so a shared pytest temp
    root makes ``tmp_path`` fail with FileExistsError - a red that would be
    about the machine, not about the guard the plant is supposed to test.
    """
    existing = os.environ.get("PYTHONPATH", "")
    pythonpath = os.pathsep.join(
        [str(ROOT / "src"), str(ROOT / "tools")] + ([existing] if existing else []))
    temp_root = cache / "pytest-tmp"
    temp_root.mkdir()
    return {**os.environ,
            "PYTHONPATH": pythonpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": str(cache),
            "TMPDIR": str(temp_root), "TMP": str(temp_root), "TEMP": str(temp_root)}


def probe_module(plant: Plant, env: dict[str, str]) -> bool:
    stem = Path(plant.filename).stem
    module = stem if plant.filename.startswith("tools/") else "autorate_portal." + stem
    proc = subprocess.run([sys.executable, "-B", "-c", PROBE, plant.name, module],
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
    before_all = {p: resolve(p).read_bytes() for p in sorted({x.filename for x in PLANTS})}
    receipts = {p: digest(data) for p, data in before_all.items()}

    fired = 0
    landed_runtime = 0
    restored = 0
    for plant in PLANTS:
        path = resolve(plant.filename)
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
    # A marker is an *assignment* appended to a mutated module. The harness
    # itself quotes the marker name in its own source, so a substring search
    # would report itself as a leftover and turn a clean run into a false red.
    planted = re.compile(r"^_PLANT_LANDED_MARKER\s*=", re.M)
    leftover = [str(p.relative_to(ROOT)) for p in (*SRC.glob("*.py"), *(ROOT / "tools").glob("*.py"))
                if planted.search(p.read_text())]
    print("PLANT SUMMARY total=%d runtime_landed=%d red=%d restored=%d leftover_markers=%s"
          % (len(PLANTS), landed_runtime, fired, restored, leftover))
    verdict = (fired == len(PLANTS) and landed_runtime == len(PLANTS)
               and restored == len(PLANTS) and not leftover)
    print("PLANT VERDICT: %s" % ("ALL RED, ALL RESTORED" if verdict else "FAILED"))
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
