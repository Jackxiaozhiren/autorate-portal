"""T9 - the pinned-distribution registry can contradict a packet (Section 7 M2)."""
from __future__ import annotations

import json

import pytest

from autorate_portal.distributions import load_registry, resolve

RELEASED_SHA = "7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205"


def _write(tmp_path, pins):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"schema": "test", "pins": pins}), encoding="utf-8")
    return path


def _pin(**overrides):
    pin = {"name": "autorate", "version": "0.1.2",
           "wheel": "autorate-0.1.2-py3-none-any.whl", "sha256": RELEASED_SHA,
           "source": "https://pypi.org/pypi/autorate/0.1.2/json"}
    pin.update(overrides)
    return pin


def test_the_packaged_registry_pins_the_released_wheel():
    registry, problems = load_registry()
    assert problems == []
    pin = registry.get("autorate", "0.1.2")
    assert pin is not None
    assert pin.wheel == "autorate-0.1.2-py3-none-any.whl"
    assert pin.sha256 == RELEASED_SHA
    assert registry.versions() == ("0.1.2",)


def test_an_unregistered_version_is_refused_and_names_what_is_registered():
    registry, _ = load_registry()
    pin, refusals = resolve(registry, version="0.1.1",
                            wheel="autorate-0.1.1-py3-none-any.whl", sha256="a" * 64)
    assert pin is None
    assert refusals[0].reason == "distribution not in the pinned registry"
    assert "0.1.2" in refusals[0].expected
    assert refusals[0].actual == "0.1.1"


def test_a_wheel_filename_disagreement_names_both_sides():
    registry, _ = load_registry()
    pin, refusals = resolve(registry, version="0.1.2",
                            wheel="autorate-0.1.2-cp312-cp312-macosx.whl",
                            sha256=RELEASED_SHA)
    assert pin is None
    assert refusals[0].reason == "wheel filename disagrees with the pinned registry"
    assert refusals[0].expected == "autorate-0.1.2-py3-none-any.whl"
    assert refusals[0].actual.endswith("macosx.whl")


def test_a_sha256_disagreement_names_both_sides():
    registry, _ = load_registry()
    pin, refusals = resolve(registry, version="0.1.2",
                            wheel="autorate-0.1.2-py3-none-any.whl", sha256="b" * 64)
    assert pin is None
    assert refusals[0].reason == "wheel sha256 disagrees with the pinned registry"
    assert refusals[0].expected == RELEASED_SHA
    assert refusals[0].actual == "b" * 64


def test_a_match_returns_the_pin_with_no_refusals():
    registry, _ = load_registry()
    pin, refusals = resolve(registry, version="0.1.2",
                            wheel="autorate-0.1.2-py3-none-any.whl", sha256=RELEASED_SHA)
    assert refusals == [] and pin is not None and pin.version == "0.1.2"


@pytest.mark.parametrize("mutation,reason", [
    ({"version": ""}, "missing required fields"),
    ({"sha256": "not-a-hash"}, "not 64 lowercase hex"),
    ({"wheel": "autorate-0.1.2.tar.gz"}, "not a wheel"),
    ({"source": "http://example.invalid/x.json"}, "not an https URL"),
    ({"surprise": "field"}, "fields this schema does not define"),
])
def test_a_malformed_entry_is_a_named_refusal_not_a_partial_load(tmp_path, mutation, reason):
    path = _write(tmp_path, [_pin(**mutation)])
    registry, problems = load_registry(path)
    assert len(registry) == 0
    assert problems and reason in problems[0].reason


def test_a_duplicate_version_is_refused_and_the_first_one_stands(tmp_path):
    path = _write(tmp_path, [_pin(), _pin(sha256="c" * 64)])
    registry, problems = load_registry(path)
    assert len(registry) == 1
    assert registry.get("autorate", "0.1.2").sha256 == RELEASED_SHA
    assert problems[0].reason == "duplicate registry entry; the first one stands"


def test_a_missing_registry_file_is_named_not_assumed(tmp_path):
    registry, problems = load_registry(tmp_path / "absent.json")
    assert len(registry) == 0
    assert problems[0].reason == "distribution registry not found"


def test_a_registry_with_no_pins_list_is_refused(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text('{"schema": "test"}', encoding="utf-8")
    registry, problems = load_registry(path)
    assert len(registry) == 0
    assert "no 'pins' list" in problems[0].reason
