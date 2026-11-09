"""I6 negative control: swap the pinned wheel hash, observe red, restore with a receipt.

PRD section 6.1 names this plant; section 6.2 requires proving both that the
removal landed and that the guarded comparison fired, with the observed values
recorded rather than a boolean. Run in CI:

    python tools/i6_plant.py <packet.tar> --backend uv

The planted packet is written beside the original and removed after the run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from autorate_portal.manifest import Manifest, payload_sha256  # noqa: E402
from autorate_portal.packet import read_bundle, write_bundle  # noqa: E402

WRONG_SHA256 = "0" * 64


def reseal(packet: Path, planted: Path, new_sha256: str = WRONG_SHA256):
    """Return (original bytes, planted bytes, old hash, new hash)."""
    original = packet.read_bytes()
    files = read_bundle(packet)
    document = json.loads(files.pop("manifest.json"))
    old = document["distribution"]["sha256"]
    document["distribution"]["sha256"] = new_sha256
    document["manifest_sha256"] = payload_sha256(document)
    model = Manifest.model_validate(document)
    planted_bytes = write_bundle(planted, model, files)
    return original, planted_bytes, old, new_sha256


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packet")
    parser.add_argument("--backend", choices=("container", "uv"), default="uv")
    args = parser.parse_args(argv)

    packet = Path(args.packet)
    planted = packet.with_suffix(".planted.tar")
    before = hashlib.sha256(packet.read_bytes()).hexdigest()
    original, planted_bytes, old, new = reseal(packet, planted)

    landed = planted_bytes != original
    print("PLANT landed          : %s" % landed)
    print("PLANT old wheel hash  : %s" % old)
    print("PLANT new wheel hash  : %s" % new)
    print("PLANT planted bytes   : %d (original %d)" % (len(planted_bytes), len(original)))
    if not landed:
        print("PLANT FAILED: the tamper did not change the bundle", file=sys.stderr)
        return 1

    env = {**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")}
    command = [sys.executable, "-m", "autorate_portal.cli", "verify-packet",
               str(planted), "--backend", args.backend]
    proc = subprocess.run(command, capture_output=True, text=True, env=env, timeout=900)
    output = proc.stdout + proc.stderr
    fired = (proc.returncode != 0 and "pinned wheel sha256 mismatch" in output
             and old in output and new in output and "state            : refused" in output)
    print("PLANT guard rc        : %d (non-zero required)" % proc.returncode)
    print("PLANT refusal named   : %s" % fired)
    print("PLANT stdout_sha256   : %s"
          % hashlib.sha256(output.encode("utf-8", "replace")).hexdigest())
    for line in output.splitlines():
        if ("state" in line or "reason" in line or "expected" in line
                or "actual" in line or "REFUSED" in line):
            print("PLANT | %s" % line.strip())

    packet.write_bytes(original)
    planted.unlink(missing_ok=True)
    after = hashlib.sha256(packet.read_bytes()).hexdigest()
    print("RECEIPT before        : %s" % before)
    print("RECEIPT after         : %s" % after)
    print("RESTORED              : %s" % (before == after))
    if not fired or before != after:
        print("PLANT FAILED: guard did not fire, or the tree was not restored", file=sys.stderr)
        return 1
    print("I6 PLANT: RED OBSERVED, TREE RESTORED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
