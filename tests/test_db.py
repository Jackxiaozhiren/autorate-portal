"""T2 - Section 4.3's model, and the structural half of I1 and tenant isolation."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from autorate_portal import db


def _session():
    engine = db.make_engine("sqlite://")
    db.create_all(engine)
    return engine, db.make_session(engine)()


def _packet(session, *, org="org-1", project="prj-1", manifest="a" * 64, path="protocol.json"):
    session.add(db.Org(id=org, name=org))
    session.add(db.Project(id=project, org_id=org, name=project))
    session.add(db.Packet(id="pkt-1", project_id=project, manifest_sha256=manifest,
                          protocol_digest="sha256:protocol", source_version="v1",
                          source_sha256="b" * 64, source_revision="main@abc",
                          created_by="producer@example.test", ingested_at="2026-11-10T00:00:00Z",
                          bytes=1024, retention_until=None))
    session.add(db.Artifact(id="art-1", packet_id="pkt-1", path=path, sha256="c" * 64,
                            kind="certificate"))
    session.flush()


# --- Section 4.3, table by table -------------------------------------------

def test_every_section_4_3_table_exists_with_exactly_its_columns():
    engine, _ = _session()
    actual = set(inspect(engine).get_table_names())
    assert actual == set(db.SECTION_4_3) | {"audit_row"}, "audit_row is Section 4.4's, not 4.3's"
    for table, expected in db.SECTION_4_3.items():
        columns = {column["name"] for column in inspect(engine).get_columns(table)}
        assert columns == set(expected), table


def test_a_bound_is_stored_as_text_so_it_cannot_be_averaged_by_accident():
    """I1 at the type level: REAL invites AVG; the artefact's digits are text."""
    engine, _ = _session()
    columns = {c["name"]: c["type"] for c in inspect(engine).get_columns("certificate_summary")}
    for name in ("autorate", "bound", "bound_unit", "alpha", "beta", "delta"):
        assert isinstance(columns[name], (db.String, db.Text)) or columns[name].__class__.__name__ in (
            "String", "Text", "VARCHAR"), name


AGGREGATE = re.compile(r"\b(?:sum|avg|average|mean)\s*\(|AVG\s*\(|SUM\s*\(", re.IGNORECASE)


def test_no_module_in_the_package_computes_an_aggregate():
    """I1's enforcement point: there is no arithmetic path to write a bound.

    The plant for this guard inserts a ``func.avg`` write into the summary path;
    the test must name the file and line, not merely fail.
    """
    package = Path(db.__file__).parent
    hits = []
    for source in sorted(package.glob("*.py")):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
            if AGGREGATE.search(line) and not line.lstrip().startswith("#"):
                hits.append("%s:%d: %s" % (source.name, number, line.strip()))
    assert not hits, "application arithmetic in the summary path: %s" % "; ".join(hits)


def test_record_summary_copies_and_refuses_to_assemble():
    _, session = _session()
    _packet(session)

    summary = db.record_summary(session, artifact_id="art-1", fields={
        "task": "support-triage", "backend": "gpt", "feasible": True,
        "bound": "0.87", "bound_unit": "fraction", "n_cal": 300, "n_eval": 612,
        "autorate": "0.812"})
    session.flush()

    values = db.summary_values(summary)
    assert values["bound"] == "0.87" and values["bound_unit"] == "fraction"
    assert values["n_eval"] == 612
    assert values["reason"] is None and values["n_claims"] is None, "absence stays absent"
    assert values["delta"] is None


def test_a_bound_without_its_unit_is_refused_not_guessed():
    _, session = _session()
    _packet(session)
    with pytest.raises(ValueError, match="without its unit"):
        db.record_summary(session, artifact_id="art-1",
                          fields={"task": "t", "backend": "b", "bound": "0.87"})


def test_a_field_that_is_not_a_column_is_refused_not_dropped():
    _, session = _session()
    _packet(session)
    with pytest.raises(ValueError, match="not a certificate_summary column: computed_bound"):
        db.record_summary(session, artifact_id="art-1",
                          fields={"task": "t", "backend": "b", "computed_bound": "0.9"})


# --- tenant isolation ------------------------------------------------------

def test_the_read_path_returns_only_the_named_project():
    engine, session = _session()
    _packet(session, org="org-1", project="prj-1", manifest="a" * 64)
    session.add(db.Org(id="org-2", name="org-2"))
    session.add(db.Project(id="prj-2", org_id="org-2", name="prj-2"))
    session.add(db.Packet(id="pkt-2", project_id="prj-2", manifest_sha256="d" * 64,
                          protocol_digest="sha256:p2", source_version="v1",
                          source_sha256="e" * 64, source_revision="main@def",
                          created_by="other@example.test", ingested_at="2026-11-10T00:00:00Z",
                          bytes=1, retention_until=None))
    session.add(db.Artifact(id="art-2", packet_id="pkt-2", path="cert.json",
                            sha256="f" * 64, kind="certificate"))
    db.record_summary(session, artifact_id="art-1",
                      fields={"task": "mine", "backend": "b", "bound": "1", "bound_unit": "x"})
    db.record_summary(session, artifact_id="art-2",
                      fields={"task": "theirs", "backend": "b", "bound": "2", "bound_unit": "x"})
    session.flush()

    mine = db.summaries_for_project(session, project_id="prj-1")
    assert [row.task for row in mine] == ["mine"]
    assert db.summaries_for_project(session, project_id="missing") == []


def test_re_ingesting_one_manifest_under_one_project_cannot_become_two_packets():
    engine, session = _session()
    _packet(session)
    session.commit()
    duplicate = db.Packet(id="pkt-9", project_id="prj-1", manifest_sha256="a" * 64,
                          protocol_digest="x", source_version="v1", source_sha256="y",
                          source_revision="z", created_by="w", ingested_at="2026-11-10T00:00:00Z",
                          bytes=1, retention_until=None)
    session.add(duplicate)
    with pytest.raises(IntegrityError):
        session.flush()


# --- credentials and roles -------------------------------------------------

def test_a_token_stores_a_hash_and_nothing_else():
    engine, _ = _session()
    columns = {column["name"] for column in inspect(engine).get_columns("api_token")}
    assert columns == set(db.SECTION_4_3["api_token"])
    assert not {"token", "secret", "plaintext"} & columns


def test_the_role_enum_covers_the_permission_matrix():
    """Section 4.5 grants auditor a column; Section 4.3's enum omits it.

    A role the matrix uses but the schema cannot store would make that row of
    the matrix unimplementable, so the enum follows 4.5 and the omission is
    recorded as a deviation rather than silently narrowed.
    """
    assert set(db.ROLES) == {"viewer", "producer", "compliance", "admin", "auditor"}
    engine, _ = _session()
    roles = {c["name"] for c in inspect(engine).get_columns("membership")}
    assert roles == set(db.SECTION_4_3["membership"])


def test_argv_is_stored_as_json_not_as_a_shell_string():
    assert json.loads(db.argv_json(["docker", "run", "--rm", "python:3.13-slim"])) == [
        "docker", "run", "--rm", "python:3.13-slim"]
    assert db.argv_json(["a b"]) == '["a b"]', "spaces inside an argument survive"
