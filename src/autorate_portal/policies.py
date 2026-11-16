"""Policies: AC11's read-only SDK surface, plus F7's versioned object.

What this module will not do is as important as what it does. It never computes
a bound, never averages anything, and never reads a stored summary to decide a
decision. A policy's ``budget`` must be one the certificate actually published;
its slices must be groups the artefact actually measured; and each decision's
``action``/``label`` is the CLI's vocabulary, read from the artefact's own
``feasible`` flag rather than re-derived here.

F7 rule 4 is structural: editing a policy inserts a new row with a higher
``version`` and a ``supersedes`` pointer. Nothing is overwritten. AC11's
read-only payload (Section 7, M4) keeps working on the first version and on
every later one; the only change to it is that staleness now also comes from a
monitor drift, and that the payload carries the decisions an SDK fetches.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from . import auth, db, i18n, monitor

ACTIVE = "active"
STALE = "stale"
SUPERSEDED = "superseded"

BUDGET_FIELDS = ("alpha", "delta", "beta")
ACTION_AUTO = "auto"
ACTION_ESCALATE = "escalate"
ACTION_ABSTAIN = "abstain"


class PolicyNotFound(LookupError):
    pass


class BudgetNotPublished(ValueError):
    """The policy named a budget the source artefact never published."""


class SliceNotInArtefact(ValueError):
    """The policy named a slice the source artefact never measured."""


@dataclass(frozen=True)
class PolicyPayload:
    state: str
    reason: str
    strict_conflict: bool
    body: dict

    def as_dict(self) -> dict:
        return dict(self.body)


def _json_document(data: bytes) -> dict[str, Any] | None:
    try:
        doc = json.loads(data.decode("utf-8"), parse_float=str)
    except (UnicodeDecodeError, ValueError, AttributeError):
        return None
    return doc if isinstance(doc, dict) else None


def _published_budgets(files: dict[str, bytes]) -> set[str]:
    """Every alpha/delta/beta the packet's artefacts publish, as strings.

    The certificate prints them at the top level; a slices artefact prints a
    corrected budget per group. Both are published values, so either is a
    budget a policy may name. Nothing is inferred: a value absent from every
    document is refused.
    """
    out: set[str] = set()
    for data in files.values():
        doc = _json_document(data)
        if doc is None:
            continue
        for key in BUDGET_FIELDS:
            if doc.get(key) is not None:
                out.add(str(doc[key]))
        run = doc.get("run") or {}
        for group in (run.get("per_group") or {}).values():
            for key in BUDGET_FIELDS:
                if (group or {}).get(key) is not None:
                    out.add(str(group[key]))
    return out


def _published_slices(files: dict[str, bytes]) -> dict[str, bool]:
    """group value -> the artefact's own feasible flag."""
    out: dict[str, bool] = {}
    for data in files.values():
        doc = _json_document(data)
        if doc is None:
            continue
        run = doc.get("run") or {}
        for name, group in (run.get("per_group") or {}).items():
            out[str(name)] = bool((group or {}).get("feasible"))
        for row in doc.get("slices") or []:
            if isinstance(row, dict) and row.get("value") is not None:
                out[str(row["value"])] = bool(row.get("feasible"))
    return out


def _decisions(values: list[str], groups: dict[str, bool]) -> list[dict[str, str]]:
    """One action/label pair per slice, in the CLI's vocabulary.

    A feasible group may auto; an infeasible one escalates; a group the
    artefact marked neither way abstains. The label is the group's own value —
    there is no invented human name. This is a transcription of the artefact's
    flag, not a decision recomputed from a bound.
    """
    out: list[dict[str, str]] = []
    for name in values:
        feasible = groups.get(name)
        if feasible is True:
            action, why = ACTION_AUTO, "the artefact published this group as feasible"
        elif feasible is False:
            action, why = ACTION_ESCALATE, "the artefact published this group as infeasible"
        else:
            action, why = ACTION_ABSTAIN, "the artefact published no feasibility for this group"
        out.append({"slice": name, "action": action, "label": name, "why": why})
    return out


def _check_budget(budget: str, published: set[str]) -> str:
    value = str(budget)
    if value not in published:
        raise BudgetNotPublished(
            "budget %r is not published by the source certificate; published budgets: %s"
            % (value, ", ".join(sorted(published)) or "(none)"))
    return value


def _check_slices(slices: Any, published: dict[str, bool]) -> list[str]:
    if isinstance(slices, str):
        try:
            slices = json.loads(slices)
        except ValueError as exc:
            raise SliceNotInArtefact("slices must be a list of group values") from exc
    values = [str(value) for value in (slices or [])]
    for value in values:
        if value not in published:
            raise SliceNotInArtefact(
                "slice %r is absent from the source artefact; published slices: %s"
                % (value, ", ".join(sorted(published)) or "(none)"))
    return values


def _new_policy(*, project_id: str, name: str, packet_id: str, budget: str,
                values: list[str], groups: dict[str, bool], version: int,
                supersedes: str | None) -> db.Policy:
    return db.Policy(project_id=project_id, name=name, packet_id=packet_id,
                     budget=budget, slices=json.dumps(_decisions(values, groups),
                                                      sort_keys=True, separators=(",", ":")),
                     state=ACTIVE, version=version, supersedes=supersedes)


def create_policy(session, *, project_id: str, name: str, packet_id: str,
                  budget: str, slices: Any, files: dict[str, bytes],
                  actor: str) -> db.Policy:
    """Create policy version 1, refusing a budget or slice nobody published."""
    packet = session.get(db.Packet, packet_id)
    if packet is None or packet.project_id != project_id:
        raise PolicyNotFound("packet %s is not in project %s" % (packet_id, project_id))
    published_budget = _published_budgets(files)
    groups = _published_slices(files)
    value = _check_budget(budget, published_budget)
    values = _check_slices(slices, groups)
    policy = _new_policy(project_id=project_id, name=name, packet_id=packet_id,
                         budget=value, values=values, groups=groups, version=1,
                         supersedes=None)
    session.add(policy)
    session.flush()
    auth.record_audit(session, actor=actor, project_id=project_id,
                      action="policy.create", target="policy:%s" % policy.id)
    return policy


def edit_policy(session, *, policy_id: str, files: dict[str, bytes], actor: str,
                budget: str | None = None, slices: Any = None) -> db.Policy:
    """Insert the next version; the previous row is kept, marked superseded."""
    old = session.get(db.Policy, policy_id)
    if old is None:
        raise PolicyNotFound("no policy %s" % policy_id)
    published_budget = _published_budgets(files)
    groups = _published_slices(files)
    value = _check_budget(old.budget if budget is None else budget, published_budget)
    source = old.slices if slices is None else slices
    if slices is None:
        try:
            source = [row["slice"] for row in json.loads(old.slices)]
        except (ValueError, TypeError, KeyError):
            source = []
    values = _check_slices(source, groups)
    new = _new_policy(project_id=old.project_id, name=old.name, packet_id=old.packet_id,
                      budget=value, values=values, groups=groups,
                      version=old.version + 1, supersedes=old.id)
    session.add(new)
    old.state = SUPERSEDED
    session.flush()
    auth.record_audit(session, actor=actor, project_id=old.project_id,
                      action="policy.edit", target="policy:%s" % new.id)
    return new


def _superseding_packet(session, policy: db.Policy, packet: db.Packet) -> db.Packet | None:
    statement = (select(db.Packet)
                 .where(db.Packet.project_id == policy.project_id,
                        db.Packet.protocol_digest != packet.protocol_digest,
                        db.Packet.ingested_at > packet.ingested_at)
                 .order_by(db.Packet.ingested_at))
    return session.scalars(statement).first()


def _drift_result(session, policy: db.Policy) -> db.MonitorResult | None:
    """A drift observed on this policy's packet makes the policy stale.

    The series lives in `monitor_result`; the packet it ran against lives in the
    run row's `packet_id_in`. Both are scoped to the policy's project, so a
    drift in another tenant cannot stale this policy.
    """
    statement = (select(db.MonitorResult)
                 .join(db.Run, db.MonitorResult.run_id == db.Run.id)
                 .where(db.MonitorResult.project_id == policy.project_id,
                        db.MonitorResult.verdict == monitor.DRIFT,
                        db.Run.packet_id_in == policy.packet_id))
    return session.scalars(statement).first()


def _stored_decisions(raw: str | None) -> list[dict[str, str]]:
    try:
        value = json.loads(raw or "[]")
    except (ValueError, TypeError):
        return []
    return value if isinstance(value, list) else []


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
    drift = None if newer is not None else _drift_result(session, policy)
    if newer is not None:
        state = STALE
        reason = i18n.t(locale, "msg.stale", digest=newer.protocol_digest)
    elif drift is not None:
        state = STALE
        reason = i18n.t(locale, "msg.stale_drift")
    else:
        state = ACTIVE
        reason = ""

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
        "decisions": _stored_decisions(policy.slices),
        "version": policy.version,
        "supersedes": policy.supersedes,
        "stale_because": reason,
        "sdk_shape": "F7: action/label decisions are published per slice",
    }
    return PolicyPayload(state, reason, strict and state == STALE, body)
