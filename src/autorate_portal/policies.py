"""AC11's minimum read-only policy surface (PRD 4.4, 5.11 AC11, 7).

Section 7 puts **AC11** in M4's gate while **F7** (policy creation, versioning,
SDK ``action``/``label`` semantics) is M5's deliverable. M3's deviation D1
recorded the same split. This module therefore implements only what AC11 asks
for: a read-only ``.well-known`` payload that says ``state: stale`` when the
policy's packet was superseded, and a 409 for ``strict=1``.

Staleness is read, never inferred from a stored summary: a newer packet in the
same project carrying a different ``protocol_digest`` supersedes this one
(F7 rule 3's first condition). No monitor drift is consulted (that is M5/F6),
no policy is created, edited or versioned here, and no bound is computed.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from . import db, i18n

ACTIVE = "active"
STALE = "stale"


class PolicyNotFound(LookupError):
    pass


@dataclass(frozen=True)
class PolicyPayload:
    state: str
    reason: str
    strict_conflict: bool
    body: dict

    def as_dict(self) -> dict:
        return dict(self.body)


def _superseding_packet(session, policy: db.Policy, packet: db.Packet) -> db.Packet | None:
    statement = (select(db.Packet)
                 .where(db.Packet.project_id == policy.project_id,
                        db.Packet.protocol_digest != packet.protocol_digest,
                        db.Packet.ingested_at > packet.ingested_at)
                 .order_by(db.Packet.ingested_at))
    return session.scalars(statement).first()


def sdk_payload(session, policy_id: str, *, strict: bool = False,
                locale: str = i18n.DEFAULT_LOCALE) -> PolicyPayload:
    """The payload an SDK fetches. Unknown ids are a named 404, not a stale hit."""
    policy = session.get(db.Policy, policy_id)
    if policy is None:
        raise PolicyNotFound("no policy %s" % policy_id)
    packet = session.get(db.Packet, policy.packet_id)
    if packet is None:
        raise PolicyNotFound("policy %s names a packet that is not in this store" % policy_id)

    newer = _superseding_packet(session, policy, packet)
    state = STALE if newer is not None else ACTIVE
    reason = i18n.t(locale, "msg.stale", digest=newer.protocol_digest) if newer else ""
    body = {
        "id": policy.id,
        "name": policy.name,
        "state": state,
        "packet_id": policy.packet_id,
        "protocol_digest": packet.protocol_digest,
        "superseded_by_packet_id": newer.id if newer is not None else None,
        "superseded_by_protocol_digest": newer.protocol_digest if newer is not None else None,
        "budget": policy.budget,
        "slices": policy.slices,
        "stale_because": reason,
        # F7's action/label shape is M5's; its absence is a named scope cut,
        # not a silently empty field.
        "sdk_shape": "M4 read-only; action/label arrive with F7 in M5",
    }
    return PolicyPayload(state, reason, strict and state == STALE, body)
