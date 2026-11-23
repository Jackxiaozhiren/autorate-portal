"""T4 walkthrough pack: the pack must be the suite's packet, and `check` must be able to fail.

`tools/walkthrough.py` is the first step the runbook never had — the database a facilitator
seeds by hand. Two things can go wrong with a tool like that, and only one of them is loud:

* the packet it builds drifts from the one the suite asserts against, so the readings in the
  runbook describe a file nobody is holding;
* `check` prints ten `ok` lines without being able to print a `FAIL`, which is worse than no
  preflight at all — it converts "nobody measured" into "we verified it".

Both are pinned here. The first by comparing bytes with the fixture's own build; the second by
seeding the deliberately wrong worlds and requiring the specific line to turn red.
"""
from __future__ import annotations

import json
import stat

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from autorate_portal import db
from autorate_portal.app import create_app

import walkthrough

ROOT = walkthrough.ROOT


# ------------------------------------------------------------------------------- helpers

def _packet_bytes(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _app(root, engine):
    return create_app(engine=engine, store_dir=root / "store",
                      salt=walkthrough.SALT, secret_key=walkthrough.SECRET)


def _failed(answers):
    return [answer.step for answer in answers if not answer.ok]


# ---------------------------------------------------------------------------- the packet

def test_the_pack_is_bit_for_bit_the_packet_the_suite_asserts_against(tmp_path, m4_built):
    """A second copy of the fixtures would let the suite stay green while the pack drifts."""
    _, _, raw = m4_built
    built = walkthrough.build_packet(tmp_path / "pack" / "demo.packet.tar")
    assert built.read_bytes() == raw


def test_two_builds_produce_one_file(tmp_path):
    """A facilitator who loses the tarball must be able to re-issue it and get the same one."""
    first = walkthrough.build_packet(tmp_path / "a" / "demo.packet.tar")
    second = walkthrough.build_packet(tmp_path / "b" / "demo.packet.tar")
    assert _packet_bytes(first) == _packet_bytes(second)


def test_the_build_leaves_no_staging_tree_behind(tmp_path):
    walkthrough.build_packet(tmp_path / "pack" / "demo.packet.tar")
    assert [path.name for path in (tmp_path / "pack").iterdir()] == ["demo.packet.tar"]


# ------------------------------------------------------------------------------ the seed

def test_seed_refuses_to_throw_away_a_database_it_did_not_make(tmp_path):
    walkthrough.seed(tmp_path)
    with pytest.raises(SystemExit) as refusal:
        walkthrough.seed(tmp_path)
    assert "--reset" in str(refusal.value)


def test_seed_writes_one_token_per_reader_and_keeps_them_private(tmp_path):
    world = walkthrough.seed(tmp_path)
    assert set(world.tokens) == set(walkthrough.READERS)
    assert len(set(world.tokens.values())) == len(walkthrough.READERS)
    tokens_file = tmp_path / "tokens.json"
    assert stat.S_IMODE(tokens_file.stat().st_mode) == 0o600
    assert json.loads(tokens_file.read_text()) == world.tokens


def test_the_seeded_database_answers_ready(tmp_path):
    """The seed must go through Alembic: a `create_all` database reads `schema-missing`."""
    world = walkthrough.seed(tmp_path)
    engine = db.make_engine("sqlite:///" + str(world.db))
    answered = TestClient(_app(tmp_path, engine)).get("/readyz")
    assert answered.status_code == 200, answered.text
    assert answered.json()["status"] == "ready"


# ------------------------------------------------------------------------------ the check

def test_check_passes_against_the_world_up_built(tmp_path):
    world = walkthrough.seed(tmp_path)
    engine = db.make_engine("sqlite:///" + str(world.db))
    answers = walkthrough.preflight(TestClient(_app(tmp_path, engine)), world.tokens)
    assert _failed(answers) == []
    assert len(answers) == 10


def test_certificates_are_the_only_line_that_notices_an_empty_project(tmp_path):
    """The reason `check` counts certificates at all.

    An empty project answers Q1-Q3 exactly like a measured one: `cannot_be_bounded` is the
    right answer to "never measured" and to "nothing to measure". Only the count separates
    them, and only the count would notice a facilitator who skipped the ingest.
    """
    world = walkthrough.seed(tmp_path)
    engine = db.make_engine("sqlite:///" + str(world.db))
    sessions = db.make_session(engine)
    with sessions() as session:
        session.execute(delete(db.CertificateSummary))
        session.execute(delete(db.Artifact))
        session.execute(delete(db.Packet))
        session.commit()

    answers = walkthrough.preflight(TestClient(_app(tmp_path, engine)), world.tokens)
    assert _failed(answers) == ["P1 certificates", "P2 certificates"]
    assert {a.step for a in answers if a.ok} >= {"P1 Q1", "P1 Q2", "P1 Q3",
                                                "P2 Q1", "P2 Q2", "P2 Q3"}


def test_a_missing_token_is_an_answer_not_a_crash(tmp_path):
    world = walkthrough.seed(tmp_path)
    engine = db.make_engine("sqlite:///" + str(world.db))
    answers = walkthrough.preflight(TestClient(_app(tmp_path, engine)), {"P1": world.tokens["P1"]})
    assert "P2 token" in _failed(answers)


def test_a_token_signed_with_another_salt_is_refused(tmp_path):
    """The card printed by `up` is only valid against the salt the printout carries."""
    world = walkthrough.seed(tmp_path)
    engine = db.make_engine("sqlite:///" + str(world.db))
    app = create_app(engine=engine, store_dir=tmp_path / "store",
                     salt="some-other-salt", secret_key=walkthrough.SECRET)
    answers = walkthrough.preflight(TestClient(app), world.tokens)
    assert "P1 sign-in" in _failed(answers)
