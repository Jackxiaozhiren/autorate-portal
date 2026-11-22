"""The image, driven the way a deployment drives it.

P16-P20 in ``docs/verification/2026-11-22-postgres-and-container.md`` were measured by hand with
``curl`` against two containers. Hand measurements do not re-run when the Dockerfile, the probes or
the migration command change, so this file performs the same four readings with containers and
lets CI fail when one of them stops being true:

* a replica that skipped the migration job is alive and **not ready** (P17);
* the one-shot job migrates, and the replica that was already running turns ready **without a
  restart** (P18);
* a database outage leaves the process alive and the readiness answer honest (P20);
* three replicas may start together and leave one revision (P12);
* the server runs as uid 10001, not root (P7).

They need Docker and a built image, so they skip unless ``AUTHORATE_TEST_IMAGE`` names one. The
``container`` CI job builds ``autorate-portal:ci``, sets the variable, and then refuses to pass on
a skip for the same reason the postgres job does: a job that skipped its subject is green for the
wrong reason.
"""
from __future__ import annotations

import dataclasses
import http.client
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from autorate_portal import migrate

IMAGE_ENV = "AUTHORATE_TEST_IMAGE"
SALT = "test-salt"
SECRET = "test-key"

pytestmark = pytest.mark.skipif(
    not os.environ.get(IMAGE_ENV),
    reason="%s is not set; the container job builds the image and names it" % IMAGE_ENV)


def _docker(*args: str, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess:
    done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and done.returncode != 0:
        raise AssertionError("docker %s -> %s\nstdout:\n%s\nstderr:\n%s"
                             % (" ".join(args), done.returncode, done.stdout, done.stderr))
    return done


def _http(url: str, timeout: float = 3) -> tuple[int, dict]:
    """Status and body, or ``(0, {})`` while nothing is answering yet.

    Docker's published port accepts before the container's server does and then closes the
    connection, so a probe during startup raises rather than refuses. "Not answering" is a state
    the callers poll through, not a test failure.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as answer:
            return answer.status, json.loads(answer.read())
    except urllib.error.HTTPError as refused:
        return refused.code, json.loads(refused.read())
    except (urllib.error.URLError, http.client.HTTPException, OSError):
        return 0, {}


def _wait(read, accept, *, timeout: float, what: str):
    """Poll ``read`` until ``accept`` holds; return its last answer, asserting on the deadline."""
    deadline = time.monotonic() + timeout
    answer = read()
    while not accept(*answer):
        if time.monotonic() >= deadline:
            raise AssertionError("%s: last answer was %s" % (what, answer))
        time.sleep(0.25)
        answer = read()
    return answer


@dataclasses.dataclass
class Cluster:
    image: str
    network: str
    pg: str


@dataclasses.dataclass
class Replica:
    name: str
    base: str

    def get(self, path: str) -> tuple[int, dict]:
        return _http(self.base + path)


def _db_url(cluster: Cluster) -> str:
    return "postgresql+psycopg://portal:portal@%s:5432/portal" % cluster.pg


def _pg_ready(cluster: Cluster) -> None:
    deadline = time.monotonic() + 60
    while True:
        ready = _docker("exec", cluster.pg, "pg_isready", "-U", "portal", "-d", "portal",
                        check=False)
        if ready.returncode == 0:
            return
        if time.monotonic() >= deadline:
            raise AssertionError("postgres never became ready:\n%s" % ready.stderr)
        time.sleep(0.5)


def _psql(cluster: Cluster, sql: str) -> str:
    return _docker("exec", cluster.pg, "psql", "-U", "portal", "-d", "portal",
                   "-v", "ON_ERROR_STOP=1", "-tAc", sql).stdout.strip()


@pytest.fixture(scope="module")
def cluster():
    image = os.environ.get(IMAGE_ENV, "").strip()
    if not image:
        pytest.skip("%s is not set" % IMAGE_ENV)
    suffix = "%d" % os.getpid()
    network = "at-gate-%s" % suffix
    pg = "at-gate-%s-pg" % suffix
    _docker("network", "create", network)
    try:
        _docker("run", "-d", "--name", pg, "--network", network,
                "-e", "POSTGRES_USER=portal", "-e", "POSTGRES_PASSWORD=portal",
                "-e", "POSTGRES_DB=portal", "postgres:17")
        _pg_ready(cluster := Cluster(image=image, network=network, pg=pg))
        yield cluster
    finally:
        _docker("rm", "-f", pg, check=False)
        _docker("network", "rm", network, check=False)


@pytest.fixture()
def fresh_schema(cluster):
    """An empty ``public`` schema, and a database that is running again."""
    _docker("start", cluster.pg, check=False)
    _pg_ready(cluster)
    _psql(cluster, "drop schema if exists public cascade; create schema public")
    return cluster


@pytest.fixture()
def deploy(cluster, fresh_schema):
    """Start replicas against the fresh schema; remove every one of them afterwards."""
    created: list[str] = []

    def start(*, migrate_at_boot: bool) -> Replica:
        name = "at-gate-%d-%d" % (os.getpid(), len(created) + 1)
        created.append(name)
        args = ["run", "-d", "--name", name, "--network", cluster.network,
                "-p", "127.0.0.1::8000",
                "-e", "AUTHORATE_DB_URL=" + _db_url(cluster),
                "-e", "AUTHORATE_TOKEN_SALT=" + SALT,
                "-e", "AUTHORATE_SECRET_KEY=" + SECRET]
        if not migrate_at_boot:
            args += ["-e", "AUTHORATE_MIGRATE_ON_START=0"]
        _docker(*args, cluster.image)
        published = _docker("port", name, "8000/tcp").stdout.strip()
        replica = Replica(name=name, base="http://" + published)
        try:
            _wait(lambda: replica.get("/healthz"), lambda status, _body: status == 200,
                  timeout=40, what="%s never answered /healthz" % name)
        except AssertionError:
            raise AssertionError("%s did not start:\n%s"
                                 % (name, _docker("logs", name, check=False).stdout
                                    + _docker("logs", name, check=False).stderr))
        return replica

    yield start
    for name in created:
        _docker("rm", "-f", name, check=False)


def test_a_replica_that_skips_the_job_is_alive_but_not_ready(deploy):
    """P17: this is the case a scheduler must act on -- alive, and unable to serve."""
    replica = deploy(migrate_at_boot=False)
    assert replica.get("/healthz") == (200, {"status": "ok"})
    assert replica.get("/readyz") == (503, {"status": "not-ready", "reason": "schema-missing"})


def test_the_job_migrates_and_the_running_replica_turns_ready(cluster, fresh_schema, deploy):
    """P18: the probe re-reads the schema, so the replica it already runs notices the job."""
    replica = deploy(migrate_at_boot=False)
    assert replica.get("/readyz")[1] == {"status": "not-ready", "reason": "schema-missing"}
    started = _docker("inspect", "-f", "{{.State.StartedAt}}", replica.name).stdout.strip()

    job = _docker("run", "--rm", "--network", cluster.network,
                  "-e", "AUTHORATE_DB_URL=" + _db_url(cluster),
                  "-e", "AUTHORATE_TOKEN_SALT=" + SALT,
                  "-e", "AUTHORATE_SECRET_KEY=" + SECRET,
                  cluster.image, "autorate-portal", "migrate")
    head = migrate.script_head()
    assert "schema at %s" % head in job.stdout + job.stderr, job.stdout + job.stderr

    status, body = _wait(lambda: replica.get("/readyz"),
                         lambda status, _body: status == 200,
                         timeout=20, what="the replica never turned ready")
    assert (status, body) == (200, {"status": "ready", "schema": head})
    after = _docker("inspect", "-f", "{{.State.StartedAt}}", replica.name).stdout.strip()
    assert after == started, "readiness must not require a restart"


def test_three_replicas_may_start_together(cluster, fresh_schema, deploy):
    """P12: every container migrates at boot; the lock has to make that safe."""
    replicas = [deploy(migrate_at_boot=True) for _ in range(3)]
    for replica in replicas:
        assert replica.get("/healthz")[0] == 200
    revisions = _psql(cluster, "select count(*) from alembic_version")
    assert revisions == "1", "one database, one revision row, not %s" % revisions
    for replica in replicas:
        assert replica.get("/readyz")[0] == 200


def test_a_database_outage_is_unready_but_the_container_stays_alive(cluster, fresh_schema, deploy):
    """P20: a liveness probe that read the database would turn this into a restart loop."""
    replica = deploy(migrate_at_boot=True)
    assert replica.get("/readyz")[0] == 200
    _docker("stop", cluster.pg)
    try:
        _wait(lambda: replica.get("/readyz"),
              lambda status, body: status == 503 and body.get("reason") == "database-unreachable",
              timeout=20, what="readiness never reported the outage")
        assert replica.get("/healthz") == (200, {"status": "ok"})
    finally:
        _docker("start", cluster.pg)
        _pg_ready(cluster)
    _wait(lambda: replica.get("/readyz"), lambda status, _body: status == 200,
          timeout=30, what="the replica never recovered")


def test_the_server_runs_as_the_unprivileged_user(cluster):
    """P7: uid 10001, because the image's writable path is the volume and nothing else."""
    done = _docker("run", "--rm", "--entrypoint", "id", cluster.image, "-u")
    assert done.stdout.strip() == "10001", done.stdout
