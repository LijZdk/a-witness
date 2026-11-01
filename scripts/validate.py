"""Validate a mandate and the trace that ran under it.

Checks, in order:
  1. Each file is readable JSON and matches its JSON Schema. If not, stop:
     the later checks assume a well-formed document.
  2. The trace's mandate_ref matches the mandate (id and hash).
  3. Every event's seq, prev_hash and hash form an unbroken chain.
  4. Event timestamps never go backwards, and the seal is not dated before
     the final event.
  5. Every event number cited in outcome_evidence exists in the trace.
  6. The seal covers the final event.
  7. Only if the record is intact: the journey obeyed the mandate. So far
     one rule is checked, human confirmation (see confirmation_problems).

Checks 1-6 ask "is this record genuine?". Check 7 asks "did the agent do
what it was allowed to?". The report says which kind of failure it found.

Signature checking is a Phase 2 job. The other mandate rules (price limits,
scope, expiry and so on) arrive with the Phase 3 verifier.

Usage: python scripts/validate.py <name>.mandate.json <name>.trace.json
Exit codes: 0 pass, 1 fail, 2 bad usage.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

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


def load(path):
    try:
        return json.loads(Path(path).read_text())
    except OSError as e:
        raise Unreadable(f"{path}: cannot read ({e.strerror})")
    except json.JSONDecodeError as e:
        raise Unreadable(f"{path}: not valid JSON ({e})")


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


def confirmation_problems(mandate, trace):
    """Every binding action needs its own live yes from the principal, given
    after the agent chose what to buy.

    Applies when the mandate says human_confirmation is "always". A yes only
    counts if it comes from the principal with decision "approved", and it
    is used up by one action_executed. A new selection_made also clears it,
    because a yes to one choice is not a yes to a different one.

    "above_limits" needs the price and scope rules, so it waits for Phase 3.
    """
    if mandate["human_confirmation"] != "always":
        return []
    problems = []
    approval = None
    for ev in trace["events"]:
        kind, payload = ev["type"], ev["payload"]
        if kind == "selection_made":
            approval = None
        elif kind == "human_confirmation" and ev["actor"] == "principal" and payload["decision"] == "approved":
            approval = ev["seq"]
        elif kind == "action_executed":
            if approval is None:
                amount = payload["amount_committed"]
                problems.append(
                    f"event {ev['seq']} (action_executed): the agent committed {amount['amount']} {amount['currency']} "
                    f"without an approved human_confirmation from the principal, but the mandate requires one every time"
                )
            approval = None
    return problems


def fail(problems, headline=""):
    print(f"FAIL  {headline}" if headline else "FAIL")
    for p in problems:
        print("  -", p)
    return 1


def main(argv):
    if len(argv) != 2:
        print("usage: python scripts/validate.py <name>.mandate.json <name>.trace.json", file=sys.stderr)
        return 2
    mandate_path, trace_path = argv

    try:
        mandate, trace = load(mandate_path), load(trace_path)
    except Unreadable as e:
        return fail([str(e)])

    name = Path(trace_path).name

    problems = [f"mandate {e}" for e in schema_errors(mandate, "mandate.schema.json")]
    problems += [f"trace {e}" for e in schema_errors(trace, "trace.schema.json")]
    if problems:
        return fail(problems, f"{name}: the record is malformed")

    problems = chain_problems(mandate, trace) + time_problems(trace) + evidence_problems(trace)
    if problems:
        return fail(problems, f"{name}: the record is broken or has been tampered with")

    problems = confirmation_problems(mandate, trace)
    if problems:
        return fail(problems, f"{name}: the record is intact, but the agent broke its mandate")

    setting = mandate["human_confirmation"]
    confirmation = "confirmation rule met" if setting == "always" else f"confirmation rule not checked for '{setting}' yet"
    print(f"PASS  {name}: schema ok, {len(trace['events'])} events chained to mandate, seal covers final event, {confirmation}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
