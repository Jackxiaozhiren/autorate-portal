"""Display terms for four state vocabularies that must not share one word.

The machine values are contracts and do not change; this module decides only
what a reader sees. ``certified`` meant three different things - a feasible
certificate, a replay that reproduced its denominator, and a badge whose
``verify`` exited 0 - and no screen could tell a reader which one it meant.
Each layer now gets its own term.

The coverage tests in ``tests/test_vocabulary.py`` compare these maps against
the state tuples the four modules actually declare. A state added to any of
them without a display term turns the suite red, which is the only way a
vocabulary stays closed after this commit.
"""
from __future__ import annotations

#: The four layers whose states reached a reader under one spelling.
LAYERS: dict[str, dict[str, str]] = {
    # The certificate's own feasibility. "certified" here means the statistical
    # claim holds; it is not a statement about a deployment.
    "certificate": {
        "certified": "statistically feasible",
        "refusal": "not statistically feasible",
        "unavailable": "unavailable",
    },
    # One replay attempt. "certified" here means the replay reproduced the
    # packet's stored denominator, nothing about the model.
    "run": {
        "certified": "replay-consistent",
        "mismatch": "replay-mismatch",
        "refused": "replay-refused",
        "not-run": "not run",
    },
    # The shareable badge's F8 vocabulary. "certified" here means verify exited
    # 0; the badge is a compact signal, so the visible label stays the machine
    # value and this term travels in the title.
    "badge": {
        "certified": "verify passed",
        "not-certifiable": "not certifiable",
        "drift": "drift",
        "not-run": "not run",
    },
    # A scheduled replay's verdict, copied from the CLI's exit codes.
    "monitor": {
        "holds": "holds",
        "not_certifiable": "not certifiable",
        "drift": "drift",
        "configuration_bug": "configuration bug",
        "not_run": "not run",
        "refused": "refused before observing",
        "failed": "failed",
    },
}


class UnknownState(KeyError):
    """A layer was asked to display a state its vocabulary does not carry."""


def display(layer: str, state: str) -> str:
    try:
        table = LAYERS[layer]
    except KeyError as exc:
        raise UnknownState("no display vocabulary for layer %r" % layer) from exc
    try:
        return table[state]
    except KeyError as exc:
        raise UnknownState("no display term for %s/%s" % (layer, state)) from exc


def states(layer: str) -> frozenset[str]:
    try:
        return frozenset(LAYERS[layer])
    except KeyError as exc:
        raise UnknownState("no display vocabulary for layer %r" % layer) from exc
