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
from autorate_portal.views import packet_header  # noqa: E402

from autorate_portal.fixtures import ARTEFACTS  # noqa: E402  (Section 6.3, literal)

EXPECTED_REDERIVED = "612 /612"
REDERIVED = re.compile(r"re-derived\s+([0-9]+ /[0-9]+)\s+values")
WHEEL = "autorate-0.1.2-py3-none-any.whl"
WHEEL_SHA256 = "7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205"
VERIFY = ("uv", "run", "--frozen", "autorate", "verify", "--protocol", "protocol.json")
COMPARED = ("feasible", "reason", "autorate", "bound", "bound_unit", "n_cal", "n_eval",
            "n_claims", "alpha", "beta", "delta")


def check_fixtures(frozen: Path) -> list[str]:
    """The names that are absent, so a missing artefact cannot pass silently."""
    return [name for name in ARTEFACTS if not (frozen / name).is_file()]


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
    print("PARITY FIXTURES=%d" % len(ARTEFACTS))
    if missing:
        for name in missing:
            print("PARITY MISSING %s" % name)
        print("PARITY FAIL: %d fixture(s) absent" % len(missing))
        return 1

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as work:
        work_path = Path(work)
        bundle = work_path / "parity.tar"
        manifest, _raw = build(args.frozen, bundle, source_revision=args.revision,
                               source_version="0.1.2", wheel_filename=WHEEL,
                               wheel_sha256=WHEEL_SHA256, expected_rederived=EXPECTED_REDERIVED)

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
            expected = artefact_values(document)
            stored = summary_fields(manifest, name, (args.frozen / name).read_bytes())
            for difference in compare_values({key: stored[key] for key in COMPARED}, expected):
                failures.append("%s: %s" % (name, difference))
            checked += 1
        print("PARITY VALUES=%d compared" % checked)

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
    if live != EXPECTED_REDERIVED:
        failures.append("the live reading %r is not the pinned %r" % (live, EXPECTED_REDERIVED))

    for failure in failures:
        print("PARITY MISMATCH %s" % failure)
    if failures:
        print("PARITY FAIL: %d difference(s)" % len(failures))
        return 1
    print("PARITY OK: %d artefacts byte-equal, denominators %s" % (len(ARTEFACTS), live))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
