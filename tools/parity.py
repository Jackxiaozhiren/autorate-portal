"""Section 6.3: the frozen repository's committed artefacts, rendered and compared.

Two rules make this a test rather than a demonstration.

* The fixture list is a literal. A glob built list passes when an artefact is
  absent - the exact failure this job exists to prevent - so a missing name is
  printed and the run fails.
* The comparison is against the artefact's own values, not against a second
  reading of the same parser. Values are taken with ``parse_float=str``, so
  "0.05" is compared as the file wrote it.

The `re-derived N /M` line the portal quotes is compared to a live `verify` run
in the same job, with the corpus removed so both are on the corpus-absent lane.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from autorate_portal import claims, db, exports  # noqa: E402
from autorate_portal.ingest import ingest, summary_fields  # noqa: E402
from autorate_portal.packet import build, verify_bundle  # noqa: E402
from autorate_portal.views import (Panel, packet_header, slice_companion, slice_context,  # noqa: E402
                                    slice_rows, slice_view)

from autorate_portal.fixtures import ALL_ARTEFACTS, ARTEFACTS, SLICE_ARTEFACTS  # noqa: E402

PINNED_REDERIVED = "612 /612"
REDERIVED = re.compile(r"re-derived\s+([0-9]+ /[0-9]+)\s+values")
WHEEL = "autorate-0.1.2-py3-none-any.whl"
WHEEL_SHA256 = "7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205"
VERIFY = ("uv", "run", "--frozen", "autorate", "verify", "--protocol", "protocol.json")
COMPARED = ("feasible", "reason", "autorate", "bound", "bound_unit", "n_cal", "n_eval",
            "n_claims", "alpha", "beta", "delta")


def check_fixtures(frozen: Path) -> list[str]:
    """The names that are absent, so a missing artefact cannot pass silently."""
    return [name for name in ALL_ARTEFACTS if not (frozen / name).is_file()]


def published_denominator(frozen: Path) -> str | None:
    """The `re-derived N /M` the frozen tree itself publishes, read from disk.

    Section 6.3 asks that the line the portal quotes equal a live run in the
    same job. Taking the expected value out of this tool's own constants makes
    the comparison agree with itself; reading it from the committed README makes
    a stale published number the thing that goes red.
    """
    readme = frozen / "README.md"
    if not readme.is_file():
        return None
    found = REDERIVED.search(readme.read_text(encoding="utf-8", errors="replace"))
    return found.group(1) if found else None


def slice_report(document: dict, manifest) -> tuple[int, int, list[str]]:
    """Render one slices artefact through the same calls the HTTP surface makes."""
    rows = slice_rows(document)
    html = slice_view(pooled=Panel("pooled", "certified", "", ""),
                      companion=slice_companion(document), document=document,
                      context=slice_context(manifest, document))["html"]
    problems: list[str] = []
    refused = 0
    for row in rows:
        label = "%s: %s" % (row.get("key"), row.get("value"))
        if label not in html:
            problems.append("slice row %r is not rendered" % label)
        if row.get("n_cal") is not None and row.get("n_eval") is not None:
            denominator = "n_cal=%s n_eval=%s" % (row["n_cal"], row["n_eval"])
            if denominator not in html:
                problems.append("slice %r lost its own denominator" % label)
        if row.get("feasible") is False:
            refused += 1
            reason = row.get("reason")
            if reason and reason not in html:
                problems.append("slice %r lost its reason %r" % (label, reason))
    return len(rows), refused, problems


def artefact_values(document: dict) -> dict:
    meta = document.get("meta") or {}
    at_alpha = meta.get("at_requested_alpha") or {}
    bound = document.get("conditional_error_bound")
    if bound is None:
        bound = document.get("marginal_error_bound")
    return {
        "feasible": document.get("feasible"),
        "reason": document.get("reason"),
        "autorate": document.get("autorate"),
        "bound": bound,
        "bound_unit": (at_alpha.get("bound_unit") or meta.get("bound_unit")) if bound is not None else None,
        "n_cal": document.get("n_cal"),
        "n_eval": document.get("n_eval"),
        "n_claims": document.get("n_claims"),
        "alpha": document.get("alpha"),
        "beta": document.get("beta"),
        "delta": document.get("delta"),
    }


def _norm(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    return str(value)


def compare_values(stored: dict, expected: dict) -> list[str]:
    differences = []
    for field in COMPARED:
        if _norm(stored.get(field)) != _norm(expected.get(field)):
            differences.append("%s: portal %r, artefact %r"
                               % (field, _norm(stored.get(field)), _norm(expected.get(field))))
    return differences


def parse_rederived(text: str) -> str | None:
    found = REDERIVED.search(text)
    return found.group(1) if found else None


def m4_parity(frozen: Path, manifest, packet, files: dict[str, bytes],
              session) -> tuple[list[str], dict[str, str]]:
    """Section 6.3 extended to what F4 and F5 quote from the frozen bytes.

    This is the check that keeps M4's two honesty claims honest: the audit
    lane's comparability statement is still published verbatim, the feasibility
    arithmetic still publishes no required sample size, F5's ``known_limits``
    section is byte-equal to ``protocol.json``, every F5 line carries the
    artefact's own sha256, and the real frozen packet still cannot produce
    ``bounded_refutes`` because it certifies no ``autorate``.
    """
    problems: list[str] = []
    readings: dict[str, str] = {}

    protocol = json.loads((frozen / "protocol.json").read_text(encoding="utf-8"))
    limits = protocol.get("known_limits")
    if not isinstance(limits, list) or not limits:
        problems.append("protocol.json publishes no known_limits array; F5's mandatory section has no source")
        limits = []
    readings["known_limits"] = str(len(limits))

    audit = (frozen / "docs/AUDIT.md").read_text(encoding="utf-8")
    for name, quote in claims.AUDIT_QUOTES.items():
        if quote not in audit:
            problems.append("docs/AUDIT.md no longer publishes the %s quote verbatim" % name)
    readings["audit_quotes"] = str(len(claims.AUDIT_QUOTES))

    feasibility = json.loads((frozen / "data/g1_feasibility.json").read_text(encoding="utf-8"))
    if any(key in feasibility for key in ("n_min", "required_n")):
        problems.append("g1_feasibility.json now publishes a required sample size; F4 rule 3 must be re-read")
    readings["feasibility_keys"] = ",".join(sorted(feasibility))

    built = exports.build_bundle(kind="annex_iv", manifest=manifest, packet=packet,
                                 files=files)
    if built.blocked:
        problems.append("the frozen packet's annex_iv bundle was blocked: %s" % built.block_reason)
    else:
        if tuple(built.known_limits) != tuple(limits):
            problems.append("F5's known_limits section is not byte-equal to protocol.json")
        declared = {artefact.path: artefact.sha256 for artefact in manifest.artifacts}
        for line in built.lines:
            if line["sha256"] != declared.get(line["source_path"]):
                problems.append("F5 line %s lost its source sha256" % line["source_path"])
        readings["bundle_lines"] = str(len(built.lines))
        readings["bundle_sha"] = built.bundle_sha256[:12]

    summaries = list(session.scalars(
        select(db.CertificateSummary)
        .join(db.Artifact, db.CertificateSummary.artifact_id == db.Artifact.id)
        .where(db.Artifact.packet_id == packet.id)))
    certificates = [json.loads(files[artefact.path].decode("utf-8"), parse_float=str)
                    for artefact in manifest.artifacts
                    if artefact.kind == "certificate" and artefact.path in files]
    verdict = claims.check(
        claim=claims.Claim("0.66", "autorate", "case", "resolutions"),
        summaries=summaries, packet=packet, manifest=manifest,
        audit_text=audit, feasibility=feasibility, certificates=certificates)
    readings["f4_verdict"] = verdict.verdict
    if verdict.verdict != claims.CANNOT_BE_BOUNDED:
        problems.append("the frozen packet now certifies an autorate; "
                        "M4's AC5 test-only status must be re-read")
    return problems, readings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Section 6.3 parity against the frozen repository")
    parser.add_argument("--frozen", required=True, type=Path)
    parser.add_argument("--revision", default="e9b0cf179175ab59da506115c54101eaf8f44389")
    args = parser.parse_args(argv)

    missing = check_fixtures(args.frozen)
    published = published_denominator(args.frozen)
    print("PARITY FIXTURES=%d" % len(ALL_ARTEFACTS))
    print("PARITY PUBLISHED_REDERIVED=%s" % published)
    if missing:
        for name in missing:
            print("PARITY MISSING %s" % name)
        print("PARITY FAIL: %d fixture(s) absent" % len(missing))
        return 1

    failures: list[str] = []
    expected = published or PINNED_REDERIVED
    if published is None:
        failures.append("the frozen tree publishes no `re-derived N /M` line to compare against")
    elif published != PINNED_REDERIVED:
        failures.append("the published line %r is not the pinned %r" % (published, PINNED_REDERIVED))

    with tempfile.TemporaryDirectory() as work:
        work_path = Path(work)
        bundle = work_path / "parity.tar"
        manifest, _raw = build(args.frozen, bundle, source_revision=args.revision,
                               source_version="0.1.2", wheel_filename=WHEEL,
                               wheel_sha256=WHEEL_SHA256, expected_rederived=expected)

        engine = db.make_engine("sqlite:///" + str(work_path / "parity.db"))
        db.create_all(engine)
        session = db.make_session(engine)()
        session.add(db.Org(id="org-parity", name="org-parity"))
        session.add(db.Project(id="prj-parity", org_id="org-parity", name="prj-parity"))
        session.flush()
        result = ingest(session, bundle_path=bundle, project_id="prj-parity", actor="parity",
                        store_dir=work_path / "store")
        if not result.accepted:
            print("PARITY FAIL: ingest refused the frozen packet")
            for refusal in result.refusals:
                print("  %s: %s" % (refusal.path, refusal.reason))
            return 1

        checked = 0
        for name in ARTEFACTS:
            document = json.loads((args.frozen / name).read_text(encoding="utf-8"),
                                  parse_float=str)
            artefact_expected = artefact_values(document)
            stored = summary_fields(manifest, name, (args.frozen / name).read_bytes())
            for difference in compare_values({key: stored[key] for key in COMPARED}, artefact_expected):
                failures.append("%s: %s" % (name, difference))
            checked += 1
        print("PARITY VALUES=%d compared" % checked)

        for name in SLICE_ARTEFACTS:
            document = json.loads((args.frozen / name).read_text(encoding="utf-8"),
                                  parse_float=str)
            total, refused, problems = slice_report(document, manifest)
            print("PARITY SLICES=%s rows=%d refusals=%d" % (name, total, refused))
            if total == 0:
                failures.append("%s: the portal renders no slice rows for a published slices artefact" % name)
            failures.extend("%s: %s" % (name, problem) for problem in problems)

        # M4: F4/F5 quote three more published artefacts. Compare those quotes
        # against the frozen bytes in this same job, not against a second
        # reading of the portal's own parser.
        verification = verify_bundle(bundle)
        packet_row = session.scalars(select(db.Packet)).first()
        if not verification.ok or verification.manifest is None or packet_row is None:
            failures.append("M4 parity could not re-verify the frozen bundle in this job")
        else:
            m4_problems, m4_readings = m4_parity(
                args.frozen, verification.manifest, packet_row,
                verification.files, session)
            failures.extend(m4_problems)
            for key, value in m4_readings.items():
                print("PARITY M4 %s=%s" % (key, value))

    completed = subprocess.run(list(VERIFY), cwd=str(args.frozen), capture_output=True, text=True,
                               env={**os.environ, "AUTORATE_FEISHU_ROOT": "/nonexistent",
                                    "PYTHONPATH": ""})
    live = parse_rederived(completed.stdout + completed.stderr)
    quoted = packet_header(manifest)["re_derived"]
    print("PARITY VERIFY_RC=%d" % completed.returncode)
    print("PARITY LIVE_REDERIVED=%s" % live)
    print("PARITY QUOTED_REDERIVED=%s" % quoted)
    if completed.returncode != 0:
        failures.append("a live verify in this job exited %d" % completed.returncode)
    if live != quoted:
        failures.append("the quoted line %r is not the live reading %r" % (quoted, live))
    if live != expected:
        failures.append("the live reading %r is not the published %r" % (live, expected))

    for failure in failures:
        print("PARITY MISMATCH %s" % failure)
    if failures:
        print("PARITY FAIL: %d difference(s)" % len(failures))
        return 1
    print("PARITY OK: %d artefacts compared field-by-field, %d rendered from their published shape, "
          "denominators %s" % (len(ARTEFACTS), len(SLICE_ARTEFACTS), live))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
