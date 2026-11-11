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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from autorate_portal import db  # noqa: E402
from autorate_portal.ingest import ingest, summary_fields  # noqa: E402
from autorate_portal.packet import build  # noqa: E402
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
