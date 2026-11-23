"""The V2 reader walkthrough, as three commands instead of six manual steps.

`docs/verification/v2-reader-gate-runbook.md` describes what the gate needs: two
non-author readers, one project, three questions, and a print that keeps the
verdict. The runbook could not be followed from a clean machine, because it
assumed a database somebody had already seeded by hand. This tool is that
missing first step, and one step more: it refuses to let a facilitator invite a
reader into a room that does not answer the way the runbook says it will.

    python tools/walkthrough.py up          # build the demo packet, seed, print cards
    python tools/walkthrough.py check       # after the server is up: are the answers right?

`up` builds its packet with the **test fixtures themselves** (`tests/conftest.py`)
rather than a copy of them: the M4 tree, the same build kwargs, the same builder,
so the walkthrough cannot drift from the suite. `check` signs in the way a reader
does — token in, cookie and csrf out — and asserts the three verdicts. A wrong
database fails loudly here and not in front of a person.

Nothing here is used by the product at runtime; the database it writes lives
under /tmp and holds no real data.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_ROOT = Path("/tmp/v2-walkthrough")
SALT = "walkthrough-salt"
SECRET = "walkthrough-secret"
ORG = "org-laya"
PROJECT = "prj-laya"
#: label -> (user id, email, role). P1 and P2 are the two readers the gate needs;
#: the producer is only here because ingesting a packet requires that role.
READERS = {
    "P1": ("u-ada", "ada@example.test", "compliance"),
    "P2": ("u-lin", "lin@example.test", "viewer"),
}
PRODUCER = ("u-prod", "producer@example.test", "producer")
#: The three questions, as (label, payload, expected status, expected verdict).
#: Q3 is the one that must not look like a verdict: an unparseable claim is 422.
QUESTIONS = (
    ("Q1", {"share": "0.66", "field": "confidence", "unit": "case",
            "population": "resolutions"}, 200, "cannot_be_bounded"),
    ("Q2", {"share": "0.66", "field": "autorate", "unit": "case",
            "population": "resolutions"}, 200, "cannot_be_bounded"),
    ("Q3", {"share": "0.66", "field": "", "unit": "case",
            "population": "resolutions"}, 422, None),
)
#: The fixture packet publishes seven certificate rows; a different number means
#: the packet or the ingest path changed and the runbook's readings no longer hold.
CERTIFICATES = 7


# --------------------------------------------------------------------------- packet

def _fixtures():
    """Load tests/conftest.py as a module, without pytest as the caller.

    Importing the fixtures is the point: a copy would be a second source of truth
    for the demo packet, and the suite would keep passing while the walkthrough
    drifted. pytest is a dev dependency, so a machine running this tool has it.
    """
    path = ROOT / "tests" / "conftest.py"
    spec = importlib.util.spec_from_file_location("walkthrough_fixtures", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_packet(out: Path) -> Path:
    """Build the M4 fixture packet exactly as the suite builds it."""
    from autorate_portal import packet as packet_module

    fixtures = _fixtures()
    staging = out.parent / (out.stem + "-tree")
    if staging.exists():
        shutil.rmtree(staging)
    tree = fixtures.source_tree.__wrapped__(staging)
    tree = fixtures.m4_source_tree.__wrapped__(tree)
    kwargs = fixtures.build_kwargs.__wrapped__()
    out.parent.mkdir(parents=True, exist_ok=True)
    packet_module.build(tree, out, **kwargs)
    shutil.rmtree(staging, ignore_errors=True)
    return out


# ----------------------------------------------------------------------------- seed

@dataclass
class World:
    db: Path
    store: Path
    packet: Path
    tokens: dict[str, str]
    certificates: int


def seed(root: Path, *, reset: bool = False) -> World:
    """Create the database the runbook describes, and hand out one token per reader.

    The schema comes from the migration chain, not from `create_all`. A seeded
    database that skips Alembic answers `/readyz` with `schema-missing`, and the
    one probe built to be trusted would then teach the facilitator to ignore it.
    """
    from autorate_portal import auth, db, ingest, migrate

    db_path, store, packet_path = root / "portal.db", root / "store", root / "demo.packet.tar"
    if db_path.exists() and not reset:
        raise SystemExit("%s already exists; pass --reset to throw it away" % db_path)
    if reset:
        db_path.unlink(missing_ok=True)
        shutil.rmtree(store, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    if not packet_path.exists():
        build_packet(packet_path)

    engine = db.make_engine("sqlite:///" + str(db_path))
    migrate.upgrade_to_head("sqlite:///" + str(db_path))
    sessions = db.make_session(engine)
    with sessions() as session:
        session.add(db.Org(id=ORG, name=ORG))
        session.add(db.Project(id=PROJECT, org_id=ORG, name="laya autorate"))
        for user_id, email, role in list(READERS.values()) + [PRODUCER]:
            session.add(db.User(id=user_id, email=email, display=email.split("@")[0]))
            session.add(db.Membership(user_id=user_id, org_id=ORG, role=role))
        session.flush()
        tokens = {label: auth.issue_token(session, user_id=user_id, project_id=PROJECT,
                                          salt=SALT)[0]
                  for label, (user_id, _email, _role) in READERS.items()}
        # issue_token flushes, it does not commit; without this the tokens print
        # and then the session rolls back, and every reader gets `unknown token`.
        session.commit()
        result = ingest.ingest(session, bundle_path=packet_path, project_id=PROJECT,
                               actor=PRODUCER[1], store_dir=store)
        session.commit()
        if not result.accepted:
            raise SystemExit("the demo packet was refused: %s" % result.state)
        certificates = session.query(db.CertificateSummary).count()

    (root / "tokens.json").write_text(json.dumps(tokens, indent=2), encoding="utf-8")
    os.chmod(root / "tokens.json", 0o600)
    return World(db=db_path, store=store, packet=packet_path, tokens=tokens,
                 certificates=certificates)


def serve_command(world: World, host: str, port: int) -> str:
    return ("AUTHORATE_DB_URL=sqlite:///%s AUTHORATE_TOKEN_SALT=%s "
            "AUTHORATE_SECRET_KEY=%s .venv/bin/python -m autorate_portal.cli serve "
            "--host %s --port %d --store %s"
            % (world.db, SALT, SECRET, host, port, world.store))


def lan_address() -> str:
    """The address a reader on the same network types. Falls back to localhost."""
    for interface in ("en0", "en1"):
        try:
            out = subprocess.run(["ipconfig", "getifaddr", interface],
                                 capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            break
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    return "127.0.0.1"


# ---------------------------------------------------------------------------- check

@dataclass
class Answer:
    step: str
    want: str
    got: str
    ok: bool


class LiveClient:
    """The three calls `check` needs, against a running server, with a cookie jar."""

    class Response:
        def __init__(self, status: int, raw: bytes):
            self.status_code = status
            self._raw = raw

        def json(self):
            return json.loads(self._raw.decode("utf-8", "replace"))

        @property
        def text(self):
            return self._raw.decode("utf-8", "replace")

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def _call(self, method: str, path: str, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                         headers=dict(headers or {}, **{
                                             "Content-Type": "application/json"}))
        try:
            with self.opener.open(request, timeout=10) as answer:
                return self.Response(answer.status, answer.read())
        except urllib.error.HTTPError as refused:
            return self.Response(refused.code, refused.read())
        except urllib.error.URLError as unreachable:
            raise SystemExit("nothing answered at %s (%s); start the service first, "
                             "or pass --base" % (self.base, unreachable.reason)) from unreachable

    def post(self, path: str, json=None, headers=None):  # noqa: A002 - mirrors TestClient
        return self._call("POST", path, body=json, headers=headers)

    def get(self, path: str, headers=None):
        return self._call("GET", path, headers=headers)


def preflight(client, tokens: dict[str, str]) -> list[Answer]:
    """Sign in as each reader and assert the three documented answers.

    Takes any object with TestClient's `post`/`get` signature, so the suite tests
    this against the app in-process and the facilitator runs it over HTTP.
    """
    answers: list[Answer] = []
    for label, (user_id, email, role) in READERS.items():
        token = tokens.get(label)
        if not token:
            answers.append(Answer("%s token" % label, "present", "missing", False))
            continue
        opened = client.post("/api/v1/session", json={"token": token})
        if opened.status_code != 200:
            answers.append(Answer("%s sign-in" % label, "200", str(opened.status_code), False))
            continue
        body = opened.json()
        answers.append(Answer("%s identity" % label, "%s/%s/%s" % (email, role, PROJECT),
                              "%s/%s/%s" % (body.get("actor"), body.get("role"),
                                            body.get("project_id")),
                              (body.get("actor"), body.get("role"), body.get("project_id"))
                              == (email, role, PROJECT)))
        csrf = body.get("csrf") or ""
        headers = {"x-csrf-token": csrf}

        listed = client.get("/api/v1/certificates")
        rows = listed.json() if listed.status_code == 200 else []
        answers.append(Answer("%s certificates" % label, str(CERTIFICATES),
                              str(len(rows)) if listed.status_code == 200
                              else str(listed.status_code),
                              listed.status_code == 200 and len(rows) == CERTIFICATES))

        for step, payload, status, verdict in QUESTIONS:
            answer = client.post("/api/v1/claims/check", json=payload, headers=headers)
            got = answer.status_code
            body = answer.json() if got in (200, 422) else {}
            actual = body.get("verdict") if got == 200 else body.get("detail", "")
            want = "%s %s" % (status, verdict) if verdict else str(status)
            seen = "%s %s" % (got, (actual if got == 200 else str(actual)[:60]))
            ok = got == status and (verdict is None or body.get("verdict") == verdict)
            answers.append(Answer("%s %s" % (label, step), want, seen, ok))
    return answers


def report(answers: list[Answer]) -> bool:
    width = max(len(a.step) for a in answers) + 2
    for answer in answers:
        print("%s %-*s want %-34s got %s"
              % ("ok  " if answer.ok else "FAIL", width, answer.step,
                 answer.want, answer.got))
    return all(answer.ok for answer in answers)


# ------------------------------------------------------------------------------ cli

def _up(args) -> int:
    root = Path(args.root)
    world = seed(root, reset=args.reset)
    address = args.address or lan_address()
    print("database : %s" % world.db)
    print("store    : %s" % world.store)
    print("packet   : %s (%d certificates)" % (world.packet, world.certificates))
    print()
    print("start the service in another terminal:")
    print("  cd %s && %s" % (ROOT, serve_command(world, args.host, args.port)))
    print()
    print("readers open: http://%s:%d/" % (address, args.port))
    for label, (user_id, email, role) in READERS.items():
        print("  %s (%s, %s): %s" % (label, role, email, world.tokens[label]))
    print()
    print("before anyone sits down:  .venv/bin/python tools/walkthrough.py check")
    print("reader tasks and the recording form: "
          "docs/verification/v2-reader-gate-runbook.md sections 2-4")
    return 0


def _packet(args) -> int:
    out = build_packet(Path(args.out))
    print(out)
    return 0


def _seed(args) -> int:
    world = seed(Path(args.root), reset=args.reset)
    print("%s (%d certificates)" % (world.db, world.certificates))
    for label, token in world.tokens.items():
        print("%s %s" % (label, token))
    return 0


def _check(args) -> int:
    tokens_path = Path(args.root) / "tokens.json"
    if not tokens_path.exists():
        raise SystemExit("%s is missing; run `walkthrough.py up --root %s` first"
                         % (tokens_path, args.root))
    tokens = json.loads(tokens_path.read_text(encoding="utf-8"))
    answers = preflight(LiveClient(args.base), tokens)
    return 0 if report(answers) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    up = sub.add_parser("up", help="build the packet, seed the database, print the cards")
    up.add_argument("--root", default=str(DEFAULT_ROOT))
    up.add_argument("--host", default="0.0.0.0")
    up.add_argument("--port", type=int, default=8111)
    up.add_argument("--address", default="", help="override the printed reader address")
    up.add_argument("--reset", action="store_true", help="throw the existing database away")
    up.set_defaults(run=_up)

    seed_parser = sub.add_parser("seed", help="seed only (the packet is built if missing)")
    seed_parser.add_argument("--root", default=str(DEFAULT_ROOT))
    seed_parser.add_argument("--reset", action="store_true")
    seed_parser.set_defaults(run=_seed)

    packet_parser = sub.add_parser("packet", help="build the demo packet only")
    packet_parser.add_argument("--out", default=str(DEFAULT_ROOT / "demo.packet.tar"))
    packet_parser.set_defaults(run=_packet)

    check = sub.add_parser("check", help="assert the three answers against a running server")
    check.add_argument("--base", default="http://127.0.0.1:8111")
    check.add_argument("--root", default=str(DEFAULT_ROOT))
    check.set_defaults(run=_check)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
