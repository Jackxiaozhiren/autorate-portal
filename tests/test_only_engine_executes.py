"""I5's structural half - execution has one home, and the engine computes nothing.

Section 7's M2 risk row: "engine is the only place with execution rights". That
is a claim about the import graph, so it is checked on the import graph rather
than asserted in prose: exactly one module may import ``subprocess``, and only
the engine (and the CLI that drives it) may call the replay.
"""
from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "autorate_portal"
SPAWNER = "replay.py"
ALLOWED_REPLAY_CALLERS = {"engine.py", "cli.py"}
FORBIDDEN_COMPUTE = {"numpy", "statistics", "math", "pandas", "scipy"}
FORBIDDEN_CALLS = {"sum", "mean", "median", "stdev", "pstdev", "quantile", "percentile",
                   "average", "sqrt", "round"}


def _modules():
    return sorted(path for path in SRC.glob("*.py"))


def test_only_one_module_can_spawn_a_process():
    importers = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                names = []
            if "subprocess" in names:
                importers.append(path.name)
    assert importers == [SPAWNER], "execution must live in exactly one module: %s" % importers


def test_no_module_shells_out_through_os():
    offenders = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                value = node.func.value
                if isinstance(value, ast.Name) and value.id == "os" and node.func.attr in {
                        "system", "popen", "spawnv", "execv", "execvp"}:
                    offenders.append("%s:os.%s" % (path.name, node.func.attr))
    assert offenders == []


def test_the_replay_is_called_from_the_engine_and_nowhere_else():
    callers = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "") == "replay":
                if "verify_packet" in {alias.name for alias in node.names}:
                    callers.append(path.name)
            if isinstance(node, ast.ImportFrom) and (node.module or "") == ".":
                if "replay" in {alias.name for alias in node.names}:
                    callers.append(path.name)
    assert set(callers) <= ALLOWED_REPLAY_CALLERS, "unexpected replay caller: %s" % callers
    assert "engine.py" in callers, "the engine is what drives the replay"


def test_the_engine_does_not_compute_a_number():
    """I1's spirit applied to the one module allowed to hold replay output."""
    source = (SRC / "engine.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported = [(node.module or "").split(".")[0]]
        else:
            imported = []
        assert not (set(imported) & FORBIDDEN_COMPUTE), (
            "the engine must not import a computation library: %s" % imported)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FORBIDDEN_CALLS, (
                "the engine must not compute: call to %s" % node.func.id)
