"""T8 - I2 is enforced at emit time, in one place, and refuses rather than formats."""
from __future__ import annotations

import types

import pytest

from autorate_portal import emit

MANIFEST = types.SimpleNamespace(packet_id="pkt-fixture", protocol_digest="ce43f8e29cc1",
                                 rubric={"alpha": 0.05, "beta": 0.05, "delta": 0.05,
                                         "method": "aps", "seed": 7})
CERTIFICATE = {"n_cal": 96, "n_eval": 96, "autorate": 0.42,
               "meta": {"at_requested_alpha": {"bound_unit": "case"}}}


def _values(**overrides):
    values = emit.components(MANIFEST, CERTIFICATE)
    values.update(overrides)
    return values


def test_a_complete_triple_renders_the_number_and_every_component():
    document = emit.statistic(label="autorate", value=0.42, values=_values())
    assert "<code>0.42</code>" in document
    assert "denominator: n_cal=96 n_eval=96" in document
    assert "budget/rubric: alpha=0.05 beta=0.05 delta=0.05 method=aps seed=7" in document
    assert "packet: pkt-fixture / ce43f8e29cc1" in document
    assert "bound_unit: case" in document


@pytest.mark.parametrize("key,missing", [
    ("denominator", "denominator"),
    ("budget/rubric", "budget/rubric"),
    ("packet", "packet id + protocol digest"),
    ("bound_unit", "bound_unit"),
])
def test_a_missing_component_refuses_to_emit(key, missing):
    values = _values(**{key: None})
    with pytest.raises(emit.EmitRefused) as raised:
        emit.statistic(label="autorate", value=0.42, values=values)
    assert raised.value.missing == [missing]


def test_an_empty_unit_is_absence_not_an_empty_string_beside_a_number():
    values = _values(bound_unit="")
    assert emit.missing_components(values) == ["bound_unit"]
    with pytest.raises(emit.EmitRefused):
        emit.statistic(label="autorate", value=0.42, values=values)


def test_the_triple_names_every_component_in_a_fixed_order():
    text = emit.triple_html(_values())
    assert text.index("denominator:") < text.index("budget/rubric:")
    assert text.index("budget/rubric:") < text.index("packet:")
    assert text.index("packet:") < text.index("bound_unit:")


def test_components_are_read_from_the_certificate_not_invented():
    values = emit.components(MANIFEST, {"n_cal": 12, "n_eval": 34,
                                       "meta": {"bound_unit": "claim"}})
    assert values["denominator"] == "n_cal=12 n_eval=34"
    assert values["bound_unit"] == "claim"


def test_a_rubric_with_a_missing_key_is_not_a_rubric():
    manifest = types.SimpleNamespace(packet_id="pkt", protocol_digest="abc",
                                     rubric={"alpha": 0.05, "beta": 0.05})
    values = emit.components(manifest, CERTIFICATE)
    assert values["budget/rubric"] is None
