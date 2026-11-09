"""Command surface for M1: packet build | verify | html, and verify-packet.

Exit codes (portal's own, documented in README): 0 certified, 2 usage,
3 not-run, 4 refusal/drift. A not-run state is never reported as a pass.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import EXIT_OK, EXIT_REFUSED, EXIT_USAGE, __version__
from .html import render
from .manifest import sha256_bytes
from .packet import MissingArtefact, build, verify_bundle
from .registry import ingest
from .replay import probe_environment, verify_packet

DEFAULT_WHEEL = "autorate-0.1.2-py3-none-any.whl"
DEFAULT_WHEEL_SHA256 = "7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205"
DEFAULT_VERSION = "0.1.2"
DEFAULT_EXPECTED = "612 /612"


def _print_refusals(refusals) -> None:
    for refusal in refusals:
        print("REFUSED: %s" % refusal.path)
        print("  reason  : %s" % refusal.reason)
        if refusal.expected:
            print("  expected: %s" % refusal.expected)
        if refusal.actual:
            print("  actual  : %s" % refusal.actual)
    print("nothing indexed")


def cmd_build(args) -> int:
    try:
        manifest, raw = build(
            Path(args.source), Path(args.out),
            source_revision=args.revision, source_version=args.version,
            wheel_filename=args.wheel, wheel_sha256=args.wheel_sha256,
            expected_rederived=args.expected_rederived, shareable=args.shareable)
    except MissingArtefact as exc:
        print("BUILD REFUSED: %s" % exc, file=sys.stderr)
        return EXIT_REFUSED
    except (OSError, ValueError) as exc:
        print("BUILD REFUSED: %s" % exc, file=sys.stderr)
        return EXIT_REFUSED
    print("packet_id        : %s" % manifest.packet_id)
    print("protocol_digest  : %s" % manifest.protocol_digest)
    print("manifest_sha256  : %s" % manifest.manifest_sha256)
    print("artifacts        : %d" % len(manifest.artifacts))
    print("records_excluded : %s" % manifest.records_excluded)
    print("excluded_records : %d" % len(manifest.excluded_records))
    print("bundle           : %s" % args.out)
    print("bundle_sha256    : %s" % sha256_bytes(raw))
    return EXIT_OK


def cmd_verify(args) -> int:
    verification = verify_bundle(Path(args.packet))
    if not verification.ok or verification.manifest is None:
        _print_refusals(verification.refusals)
        return EXIT_REFUSED
    manifest = verification.manifest
    print("verified %s (%d artefacts, protocol digest %s)"
          % (manifest.packet_id, len(manifest.artifacts), manifest.protocol_digest))
    if args.registry:
        row, created = ingest(Path(args.registry), manifest)
        print("registry: %s row %s; artefacts indexed: %d"
              % ("created" if created else "idempotent hit on", row["manifest_sha256"],
                 len(row["artifacts"])))
    return EXIT_OK


def cmd_html(args) -> int:
    verification = verify_bundle(Path(args.packet))
    if not verification.ok or verification.manifest is None:
        _print_refusals(verification.refusals)
        return EXIT_REFUSED
    document = render(verification.manifest, verification.files)
    Path(args.out).write_text(document, encoding="utf-8")
    print("rendered %s (%d bytes, no records rows)"
          % (args.out, len(document.encode("utf-8"))))
    return EXIT_OK


def cmd_verify_packet(args) -> int:
    env = probe_environment(image=args.image)
    outcome = verify_packet(Path(args.packet), env, backend=args.backend)
    print("state            : %s" % outcome.state)
    print("reason           : %s" % outcome.reason)
    if outcome.rederived:
        print("re-derived       : %s (packet stored %s)" % (outcome.rederived, outcome.expected))
    if outcome.refusals:
        _print_refusals(outcome.refusals)
    print("run_row          : %s" % json.dumps(outcome.run_row(), sort_keys=True))
    return outcome.rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="autorate-portal",
                                     description="M1 evidence packets for autorate")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    packet = sub.add_parser("packet", help="build, verify or render a packet")
    psub = packet.add_subparsers(dest="packet_command", required=True)

    b = psub.add_parser("build", help="build a deterministic packet from a source checkout")
    b.add_argument("--source", required=True, help="checkout holding the committed artefacts")
    b.add_argument("--out", required=True, help="output .tar path")
    b.add_argument("--revision", required=True, help="source git revision the artefacts came from")
    b.add_argument("--version", default=DEFAULT_VERSION)
    b.add_argument("--wheel", default=DEFAULT_WHEEL)
    b.add_argument("--wheel-sha256", default=DEFAULT_WHEEL_SHA256)
    b.add_argument("--expected-rederived", default=DEFAULT_EXPECTED)
    b.add_argument("--shareable", action="store_true",
                   help="exclude records artefacts and name them (PRD section 8.4)")
    b.set_defaults(fn=cmd_build)

    v = psub.add_parser("verify", help="verify packet integrity (AC1)")
    v.add_argument("packet")
    v.add_argument("--registry", default=None, help="optional idempotent registry JSON path (AC14)")
    v.set_defaults(fn=cmd_verify)

    h = psub.add_parser("html", help="render a self-contained HTML view")
    h.add_argument("packet")
    h.add_argument("-o", "--out", required=True)
    h.set_defaults(fn=cmd_html)

    r = sub.add_parser("verify-packet", help="replay a packet with the pinned distribution (AC9/AC10)")
    r.add_argument("packet")
    r.add_argument("--backend", choices=("container", "uv"), default="container")
    r.add_argument("--image", default="python:3.13-slim")
    r.set_defaults(fn=cmd_verify_packet)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (OSError, ValueError) as exc:
        print("%s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
