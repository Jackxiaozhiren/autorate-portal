"""T4: the server has one launch path, and the image cannot carry a credential.

The portal had no `serve` command and no server dependency before this task, so
there was nothing for an image to run. These tests cover the two halves that can
be checked without building the image: the command refuses before it binds, and
the container definition keeps the properties the deployment relies on.
"""
from __future__ import annotations

import sys
from pathlib import Path

from autorate_portal.cli import main

ROOT = Path(__file__).resolve().parents[1]
SALT_ENV = "AUTHORATE_TOKEN_SALT"
SECRET_ENV = "AUTHORATE_SECRET_KEY"


class _UvicornStub:
    def __init__(self):
        self.calls = []

    def run(self, app, **kwargs):
        self.calls.append((app, kwargs))


def _clear(monkeypatch):
    monkeypatch.delenv(SALT_ENV, raising=False)
    monkeypatch.delenv(SECRET_ENV, raising=False)


def test_serve_refuses_to_bind_on_the_packaged_credentials(monkeypatch, capsys):
    _clear(monkeypatch)
    stub = _UvicornStub()
    monkeypatch.setitem(sys.modules, "uvicorn", stub)
    assert main(["serve", "--port", "0"]) == 2
    assert stub.calls == []
    assert "REFUSING TO START" in capsys.readouterr().err


def test_serve_starts_uvicorn_with_the_app_and_the_requested_address(monkeypatch, tmp_path):
    monkeypatch.setenv(SALT_ENV, "a-salt-that-is-not-in-the-source")
    monkeypatch.setenv(SECRET_ENV, "a-secret-that-is-not-in-the-source")
    monkeypatch.setenv("AUTHORATE_DB_URL", "sqlite://")
    stub = _UvicornStub()
    monkeypatch.setitem(sys.modules, "uvicorn", stub)

    code = main(["serve", "--host", "127.0.0.1", "--port", "18000", "--store", str(tmp_path)])

    assert code == 0
    assert len(stub.calls) == 1
    app, kwargs = stub.calls[0]
    assert kwargs == {"host": "127.0.0.1", "port": 18000}
    assert any(getattr(route, "path", "") == "/healthz" for route in app.routes)


def test_the_image_copies_no_environment_file_and_migrates_before_serving():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert ".env" not in text
    assert "COPY . " not in text and "COPY .\n" not in text
    assert SALT_ENV + "=" not in text and SECRET_ENV + "=" not in text
    # The migration step must be the locked command, not bare `alembic`: replicas start
    # together, and an unlocked upgrade is the race described in autorate_portal.migrate.
    assert text.index("autorate-portal migrate --if-enabled") < text.index("autorate-portal serve")
    assert "exec autorate-portal serve" in text


def test_the_image_runs_as_a_non_root_user_and_exposes_the_port():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER portal" in text and "USER root" not in text
    assert "EXPOSE 8000" in text


def test_the_dockerignore_excludes_the_environment_file():
    lines = {line.strip() for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()}
    assert ".env" in lines and ".env.*" in lines
