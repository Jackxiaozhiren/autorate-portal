"""F9's share link: a signed, expiring grant — never a records exposure.

A share token is a compact, HMAC-signed record of three things: the packet id,
that packet's manifest hash, and an absolute expiry. The portal does not keep a
share table: it verifies the signature and the expiry on every request, so a
link cannot be silently extended, and a tampered packet id resolves to nothing.
The reader never needs a project token — that is the point of a public share —
but the document the link serves is the *same bytes* the CLI renders (F9 rule 4).

The expiry is absolute seconds since the epoch. The test seam is an injected
``now``; production takes the wall clock. Expired and tampered links are
separate, named failures so a 410 (gone) is never reported as a 404 (wrong id).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass


class Invalid(ValueError):
    """The signature or the payload is not one this portal minted."""


class Expired(ValueError):
    """A genuine grant whose expiry has passed."""


@dataclass(frozen=True)
class ShareGrant:
    packet_id: str
    manifest_sha256: str
    expires_at: int

    def headers(self) -> dict[str, str]:
        return {"x-share-packet-id": self.packet_id,
                "x-share-expires-at": str(self.expires_at)}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint(*, packet_id: str, manifest_sha256: str, ttl_seconds: int,
         secret: str, now: int | None = None) -> str:
    """Sign a grant. A non-positive TTL mints an already-expired link."""
    if not packet_id or not manifest_sha256:
        raise Invalid("a share needs a packet id and a manifest hash")
    expiry = int((time.time() if now is None else now)) + int(ttl_seconds)
    payload = json.dumps({"packet_id": packet_id, "manifest_sha256": manifest_sha256,
                          "expires_at": expiry}, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    body = _b64(payload)
    signature = _b64(hmac.new(secret.encode("utf-8"), body.encode("ascii"),
                              hashlib.sha256).digest())
    return "%s.%s" % (body, signature)


def resolve(token: str, *, secret: str, now: int | None = None) -> ShareGrant:
    """Verify then decode. Signature failures and expiry are distinct."""
    if not isinstance(token, str) or token.count(".") != 1:
        raise Invalid("not a share token")
    body, signature = token.split(".")
    expected = _b64(hmac.new(secret.encode("utf-8"), body.encode("ascii"),
                             hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        raise Invalid("share token signature does not verify")
    try:
        payload = json.loads(_unb64(body))
        packet_id = payload["packet_id"]
        manifest_sha256 = payload["manifest_sha256"]
        expires_at = int(payload["expires_at"])
    except (ValueError, KeyError, TypeError) as exc:
        raise Invalid("share token payload is malformed") from exc
    current = int(time.time() if now is None else now)
    if current >= expires_at:
        raise Expired("this share link expired at %d" % expires_at)
    return ShareGrant(packet_id, manifest_sha256, expires_at)
