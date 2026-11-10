"""T10 - doctor reaches the not-run verdict before a replay is spent (M2, AC10)."""
from __future__ import annotations

from autorate_portal import EXIT_NOT_RUN, EXIT_OK
from autorate_portal.doctor import exit_code, examine, render
from autorate_portal.replay import Environment
from conftest import tamper_bundle


def _env(*, docker=True, network=True):
    return Environment(docker_available=docker, network_available=network,
                       docker_detail="docker daemon unavailable (injected)",
                       network_detail="PyPI unreachable (injected)")


def _check(checks, name):
    return next(check for check in checks if check.name == name)


def _examine(**kwargs):
    """Stub the container-egress probe: a unit test must not start a container."""
    kwargs.setdefault("container_probe", lambda image: (True, "%s reaches PyPI (stub)" % image))
    return examine(**kwargs)


def test_a_ready_machine_has_no_failing_check(built):
    checks = _examine(backend="container", packet_path=built[0], env=_env())
    assert [check.name for check in checks] == [
        "python", "version", "database", "uv", "docker", "container-network", "pypi",
        "registry", "packet"]
    assert [check.name for check in checks if check.status == "fail"] == []
    assert exit_code(checks) == EXIT_OK


def test_missing_docker_fails_the_container_backend_and_exits_not_run():
    checks = _examine(backend="container", env=_env(docker=False))
    docker = _check(checks, "docker")
    assert docker.status == "fail"
    assert "docker daemon unavailable" in docker.detail
    assert exit_code(checks) == EXIT_NOT_RUN


def test_the_uv_backend_does_not_require_docker():
    checks = _examine(backend="uv", env=_env(docker=False))
    assert _check(checks, "docker").status == "not-required"
    assert exit_code(checks) == EXIT_OK


def test_missing_network_fails_every_backend():
    for backend in ("container", "uv"):
        checks = _examine(backend=backend, env=_env(network=False))
        assert _check(checks, "pypi").status == "fail"
        assert exit_code(checks) == EXIT_NOT_RUN


def test_doctor_does_not_speak_the_certificate_vocabulary(built):
    text = render(_examine(backend="container", packet_path=built[0], env=_env())).lower()
    for word in ("certified", "certifies", "certificate"):
        assert word not in text


def test_a_usable_registry_is_reported_with_its_pins():
    registry = _check(_examine(backend="container", env=_env()), "registry")
    assert registry.status == "ok" and "autorate==0.1.2" in registry.detail


def test_a_broken_registry_is_a_failing_check(tmp_path):
    broken = tmp_path / "pins.json"
    broken.write_text("{}", encoding="utf-8")
    checks = _examine(backend="container", registry_path=broken, env=_env())
    assert _check(checks, "registry").status == "fail"
    assert exit_code(checks) == EXIT_NOT_RUN


def test_a_tampered_packet_is_a_failing_check(built):
    tamper_bundle(built[0], "data/cert_laya.json", b"tampered")
    checks = _examine(backend="container", packet_path=built[0], env=_env())
    packet = _check(checks, "packet")
    assert packet.status == "fail"
    assert "data/cert_laya.json" in packet.detail
    assert exit_code(checks) == EXIT_NOT_RUN


def test_no_packet_is_reported_as_not_required_rather_than_ok():
    checks = _examine(backend="container", env=_env())
    assert _check(checks, "packet").status == "not-required"
    assert exit_code(checks) == EXIT_OK


def test_the_rendered_table_has_one_line_per_check():
    checks = _examine(backend="container", env=_env())
    lines = render(checks).splitlines()
    assert len(lines) == len(checks)
    for check, line in zip(checks, lines):
        assert line.split()[0] == check.name
        assert check.status in line


def test_container_without_egress_is_a_failing_check():
    """The host can reach PyPI; the container cannot. Only one of those is visible from here."""
    checks = _examine(backend="container", env=_env(),
                      container_probe=lambda image: (False, "container cannot reach PyPI: unreachable"))
    check = _check(checks, "container-network")
    assert check.status == "fail"
    assert "cannot reach PyPI" in check.detail
    assert exit_code(checks) == EXIT_NOT_RUN


def test_the_uv_backend_does_not_probe_a_container():
    checks = _examine(backend="uv", env=_env())
    assert _check(checks, "container-network").status == "not-required"
    assert exit_code(checks) == EXIT_OK


def test_the_container_probe_is_named_when_docker_itself_failed():
    checks = _examine(backend="container", env=_env(docker=False))
    assert _check(checks, "container-network").status == "not-required"
    assert _check(checks, "docker").status == "fail"


def test_the_version_row_names_the_pinned_distribution():
    checks = _examine(backend="uv", env=_env())
    version = _check(checks, "version")
    assert version.status == "ok"
    assert "portal" in version.detail and "autorate==0.1.2" in version.detail


def test_a_reachable_database_is_ok(tmp_path):
    checks = _examine(backend="uv", env=_env(), db_url="sqlite:///" + str(tmp_path / "p.db"))
    assert _check(checks, "database").status == "ok"


def test_an_unreachable_database_fails_the_check_and_exits_not_run(tmp_path):
    checks = _examine(backend="uv", env=_env(),
                      db_url="sqlite:///" + str(tmp_path / "missing" / "x.db"))
    database = _check(checks, "database")
    assert database.status == "fail" and database.detail
    assert exit_code(checks) == EXIT_NOT_RUN


def test_a_password_in_the_database_url_is_not_printed():
    checks = _examine(backend="uv", env=_env(),
                      db_url="postgresql://user:hunter2@127.0.0.1:9/none")
    detail = _check(checks, "database").detail
    assert "hunter2" not in detail and "***" in detail
