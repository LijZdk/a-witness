"""Validate a mandate and the trace that ran under it.

Checks, in order:
  1. Each file is readable JSON and matches its JSON Schema. If not, stop:
     the later checks assume a well-formed document.
  2. The trace's mandate_ref matches the mandate (id and hash).
  3. Every event's seq, prev_hash and hash form an unbroken chain.
  4. Event timestamps never go backwards, and the seal is not dated before
     the final event.
  5. Every event number cited in outcome_evidence exists in the trace.
  6. Every quote_received has a unique quote_id, and every quote an event
     refers to was received earlier in the trace.
  7. The seal covers the final event.
  8. With --keys: the principal signed the mandate, every seal signature is
     valid, and the agent the mandate names signed the seal with its key.
  9. Only if the record is intact: the journey obeyed the mandate. So far
     one rule is checked, human confirmation (see confirmation_problems).

Checks 1-8 ask "is this record genuine?". Check 9 asks "did the agent do
what it was allowed to?". The report says which kind of failure it found.

The other mandate rules (price limits, scope, expiry and so on) arrive with
the Phase 3 verifier.

Usage: python scripts/validate.py <name>.mandate.json <name>.trace.json [--keys <keys>.jwks.json]
Exit codes: 0 pass, 1 fail, 2 bad usage.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

import jws
from chain import event_hash, mandate_hash

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = {name: json.loads((ROOT / "schemas" / name).read_text())
           for name in ("mandate.schema.json", "trace.schema.json")}
# The trace schema reuses definitions from the mandate schema by $id.
REGISTRY = Registry().with_resources(
    (s["$id"], Resource.from_contents(s)) for s in SCHEMAS.values()
)


class Unreadable(Exception):
    pass


# The same limit as the Go verifier (witness/canon.MaxDepth; SPEC.md, "Canonical JSON").
MAX_DEPTH = 1000


def too_deep(text):
    """True if arrays and objects nest deeper than MAX_DEPTH. A scan, not a parse, so it cannot recurse."""
    depth, in_string, escaped = 0, False, False
    for c in text:
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return True
        elif c in "]}":
            depth -= 1
    return False


def load(path):
    try:
        text = Path(path).read_text()
        if too_deep(text):
            raise Unreadable(f"{path}: nested deeper than {MAX_DEPTH} levels")
        return json.loads(text)
    except OSError as e:
        raise Unreadable(f"{path}: cannot read ({e.strerror})")
    except json.JSONDecodeError as e:
        raise Unreadable(f"{path}: not valid JSON ({e})")
    except RecursionError:
        raise Unreadable(f"{path}: nested too deeply to read")


def describe(error):
    """jsonschema's message, except where it would dump the whole object instead of saying what is wrong."""
    branches = error.validator_value
    if error.validator == "anyOf" and all(set(b) == {"required"} for b in branches):
        return "needs at least one of: " + ", ".join(f for b in branches for f in b["required"])
    return error.message


def schema_errors(doc, schema_name):
    v = Draft202012Validator(SCHEMAS[schema_name], registry=REGISTRY, format_checker=FormatChecker())
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {describe(e)}"
            for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))]


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def chain_problems(mandate, trace):
    problems = []
    events = trace["events"]

    expected_mandate_hash = mandate_hash(mandate)
    if trace["mandate_ref"]["mandate_hash"] != expected_mandate_hash:
        problems.append("trace mandate_ref.mandate_hash does not match the mandate")
    if trace["mandate_ref"]["mandate_id"] != mandate["mandate_id"]:
        problems.append("trace mandate_ref.mandate_id does not match the mandate")

    prev = expected_mandate_hash
    for i, ev in enumerate(events):
        if ev["seq"] != i:
            problems.append(f"event {i}: seq is {ev['seq']}, expected {i}")
        if ev["prev_hash"] != prev:
            problems.append(f"event {i}: prev_hash breaks the chain")
        if ev["hash"] != event_hash(ev):
            problems.append(f"event {i}: hash does not match its content (tampered?)")
        prev = ev["hash"]

    if trace["seal"]["final_event_hash"] != prev:
        problems.append("seal does not cover the final event")

    return problems


def time_problems(trace):
    problems = []
    try:
        times = [parse_time(ev["at"]) for ev in trace["events"]]
        sealed_at = parse_time(trace["seal"]["sealed_at"])
    except ValueError as e:
        return [f"unreadable timestamp: {e}"]
    for i in range(1, len(times)):
        if times[i] < times[i - 1]:
            problems.append(f"event {i}: timestamp is earlier than event {i - 1}")
    if sealed_at < times[-1]:
        problems.append("seal is dated before the final event")
    return problems


def evidence_problems(trace):
    problems = []
    count = len(trace["events"])
    for outcome, ref in trace.get("outcome_evidence", {}).items():
        for seq in ref["event_seqs"]:
            if seq >= count:
                problems.append(f"outcome_evidence.{outcome} cites event {seq}, but the trace has only {count} events")
    return problems


def quote_refs(event):
    """The quote ids an event refers to, by event type. quote_received defines ids; it does not refer to them."""
    p, kind = event["payload"], event["type"]
    if kind in ("requirement_check", "selection_made", "action_executed"):
        return [p["quote_id"]]
    if kind == "alternatives_considered":
        return [o["quote_id"] for o in p["options"]]
    if kind in ("escalation", "error") and "related_quote_id" in p:
        return [p["related_quote_id"]]
    return []


def reference_problems(trace):
    """Each quote_received has its own quote_id, and every quote an event refers to
    was received earlier in the same trace. Otherwise a reviewer cannot tell which
    offer a check, a choice or a purchase was about."""
    problems = []
    received = {}  # quote_id -> seq of the quote_received that introduced it
    for ev in trace["events"]:
        seq, kind = ev["seq"], ev["type"]
        if kind == "quote_received":
            qid = ev["payload"]["quote_id"]
            if qid in received:
                problems.append(f"event {seq} (quote_received): quote_id '{qid}' was already used by event {received[qid]}")
            else:
                received[qid] = seq
        for qid in quote_refs(ev):
            if qid not in received:
                problems.append(f"event {seq} ({kind}): refers to quote '{qid}', but no earlier quote_received offered it")
    return problems


def confirmation_problems(mandate, trace):
    """Every binding action needs its own live yes from the principal, given
    after the agent chose what to buy and for the quote it chose.

    Applies when the mandate says human_confirmation is "always". A yes only
    counts if it comes from the principal with decision "approved", after a
    selection_made. It is used up by one action_executed, and that action must
    be on the quote that was selected. A new selection_made cancels it, because
    a yes to one choice is not a yes to a different one; so does a later
    human_confirmation that is declined or modified.

    "above_limits" needs the price and scope rules, so it waits for Phase 3.
    """
    if mandate["human_confirmation"] != "always":
        return []
    problems = []
    selected = None        # quote_id of the latest selection_made
    approved_quote = None  # the quote a pending approval is for; None if none is pending
    for ev in trace["events"]:
        kind, payload = ev["type"], ev["payload"]
        if kind == "selection_made":
            selected = payload["quote_id"]
            approved_quote = None
        elif kind == "human_confirmation":
            if payload["decision"] == "approved":
                if ev["actor"] == "principal":
                    # Before any selection_made, selected is None: the yes is for no choice, so no yes is pending.
                    approved_quote = selected
            else:
                approved_quote = None
        elif kind == "action_executed":
            amount = payload["amount_committed"]
            committed = f"{amount['amount']} {amount['currency']}"
            if approved_quote is None:
                problems.append(
                    f"event {ev['seq']} (action_executed): the agent committed {committed} "
                    f"without an approved human_confirmation from the principal, but the mandate requires one every time"
                )
            elif payload["quote_id"] != approved_quote:
                problems.append(
                    f"event {ev['seq']} (action_executed): the agent committed {committed} "
                    f"on quote '{payload['quote_id']}', but the principal approved quote '{approved_quote}'"
                )
            approved_quote = None
    return problems


def fail(problems, headline=""):
    print(f"FAIL  {headline}" if headline else "FAIL")
    for p in problems:
        print("  -", p)
    return 1


def signature_problems(mandate, trace, keys):
    """SPEC.md rule 15. keys maps key ids to public keys: which keys to trust."""
    problems = []

    def check(sig, where, typ, payload):
        key = keys.get(sig["key_id"])
        if key is None:
            problems.append(f"{where}: key {sig['key_id']!r} is not in the key file")
            return False
        try:
            jws.verify(sig["value"], payload, key, sig["alg"], sig["key_id"], typ)
            return True
        except ValueError as e:
            problems.append(f"{where} does not verify: {e}")
            return False

    check(mandate["signature"], "mandate signature", jws.MANDATE_TYP, jws.mandate_payload(mandate))
    agent_key = mandate["agent"].get("public_key_ref")
    payload = jws.seal_payload(trace)
    agent_signed = False
    for i, sig in enumerate(trace["seal"]["signatures"]):
        valid = check(sig, f"seal signature {i} ({sig['signer']})", jws.SEAL_TYP, payload)
        if sig["signer"] != "agent":
            continue
        if agent_key and sig["key_id"] != agent_key:
            problems.append(f"seal signature {i} (agent) uses key {sig['key_id']!r}, but the mandate names the agent's key as {agent_key!r}")
            continue
        agent_signed = agent_signed or valid
    if not agent_signed:
        problems.append("the seal has no valid signature from the agent the mandate names")
    return problems


USAGE = "usage: python scripts/validate.py <name>.mandate.json <name>.trace.json [--keys <keys>.jwks.json]"


def run(argv):
    keys_path = None
    if len(argv) == 4 and argv[2] == "--keys":
        keys_path = argv[3]
    elif len(argv) != 2:
        print(USAGE, file=sys.stderr)
        return 2
    mandate_path, trace_path = argv[:2]

    try:
        mandate, trace = load(mandate_path), load(trace_path)
        keys = jws.load_jwks(keys_path) if keys_path else None
    except Unreadable as e:
        return fail([str(e)])
    except (OSError, ValueError, KeyError) as e:
        return fail([f"{keys_path}: cannot read the key file ({e})"])

    name = Path(trace_path).name

    problems = [f"mandate {e}" for e in schema_errors(mandate, "mandate.schema.json")]
    problems += [f"trace {e}" for e in schema_errors(trace, "trace.schema.json")]
    if problems:
        return fail(problems, f"{name}: the record is malformed")

    problems = (chain_problems(mandate, trace) + time_problems(trace)
                + evidence_problems(trace) + reference_problems(trace))
    if keys is not None:
        problems += signature_problems(mandate, trace, keys)
    if problems:
        return fail(problems, f"{name}: the record is broken or has been tampered with")

    problems = confirmation_problems(mandate, trace)
    if problems:
        return fail(problems, f"{name}: the record is intact, but the agent broke its mandate")

    setting = mandate["human_confirmation"]
    confirmation = "confirmation rule met" if setting == "always" else f"confirmation rule not checked for '{setting}' yet"
    signatures = "signatures valid" if keys is not None else "signatures NOT checked (no --keys)"
    print(f"PASS  {name}: schema ok, {len(trace['events'])} events chained to mandate, seal covers final event, {signatures}, {confirmation}")
    return 0


def main(argv):
    """run(), except that a document nested so deeply that some library recurses past Python's
    limit (schema validation, canonicalisation, a JWS header, the key file) is a clean FAIL."""
    try:
        return run(argv)
    except RecursionError:
        return fail(["the document is nested too deeply to check"])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
