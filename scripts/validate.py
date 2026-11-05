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
  8. Signatures (SPEC.md rule 15), against keys the verifier trusts for each
     role: the mandate is signed with a principal key; the agent the mandate
     names signed the seal with exactly the key it names; a provider signed
     the seal with a provider key; with --require-principal-seal, the
     principal did too. The role files must be disjoint: see signature_problems
     for exactly which cross-role overlaps are caught.
     Each human_confirmation that carries a principal_signature is checked
     too (see signature_problems, step 6).
  9. Only if the record is intact: the journey obeyed the mandate. So far
     one rule is checked, human confirmation (see confirmation_problems).
     With --require-signed-confirmations, only approvals the principal
     signed count.

Checks 1-8 ask "is this record genuine?". Check 9 asks "did the agent do
what it was allowed to?". The report says which kind of failure it found.

The other mandate rules (price limits, scope, expiry and so on) arrive with
the Phase 3 verifier.

Usage:
  python scripts/validate.py M T --principal-keys F --provider-keys F --agent-keys F [--require-principal-seal] [--require-signed-confirmations]
  python scripts/validate.py M T --skip-signatures

Each F is a plain JWKS file, read from disk, so which keys are trusted for
which role is decided by the files you give, never by a key id inside the
documents. (The Go verifier can also pin JWKS URLs; this script reads files.)
Choose the files to hold only the parties to the journey being checked. With
--skip-signatures nothing about the signatures is checked and the result is
never a PASS.

Exit codes: 0 pass, 1 fail, 2 bad usage.
"""
import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
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


def _refuse_duplicates(pairs):
    """Like the Go verifier (witness/canon), refuse an object that repeats a key."""
    seen = set()
    for name, _ in pairs:
        if name in seen:
            raise ValueError(f"duplicate object key '{esc(name)}'")
        seen.add(name)
    return dict(pairs)


SURROGATE = re.compile("[" + chr(0xD800) + "-" + chr(0xDFFF) + "]")


def has_lone_surrogate(doc):
    """True if any string or object key in doc holds a surrogate (from a \\ud800 escape): the
    Go verifier refuses these too. Iterative, so depth cannot recurse."""
    stack = [doc]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if SURROGATE.search(v):
                return True
        elif isinstance(v, list):
            stack.extend(v)
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
    return False


def load(path):
    shown = esc(str(path))
    try:
        text = Path(path).read_text(encoding="utf-8")
        if too_deep(text):
            raise Unreadable(f"{shown}: nested deeper than {MAX_DEPTH} levels")
        doc = json.loads(text, object_pairs_hook=_refuse_duplicates)
        if has_lone_surrogate(doc):
            raise Unreadable(f"{shown}: holds a lone surrogate, which is not valid text")
        return doc
    except OSError as e:
        raise Unreadable(f"{shown}: cannot read ({e.strerror})")
    except UnicodeDecodeError:
        raise Unreadable(f"{shown}: not valid UTF-8")
    except json.JSONDecodeError as e:
        raise Unreadable(f"{shown}: not valid JSON ({e})")
    except ValueError as e:
        raise Unreadable(f"{shown}: {e}")
    except RecursionError:
        raise Unreadable(f"{shown}: nested too deeply to read")


def describe(error):
    """jsonschema's message, except where it would dump the whole object instead of saying what is wrong."""
    branches = error.validator_value
    if error.validator == "anyOf" and all(set(b) == {"required"} for b in branches):
        return "needs at least one of: " + ", ".join(f for b in branches for f in b["required"])
    return error.message


def schema_errors(doc, schema_name):
    v = Draft202012Validator(SCHEMAS[schema_name], registry=REGISTRY, format_checker=FormatChecker())
    return [f"{esc('/'.join(map(str, e.absolute_path))) or '<root>'}: {esc(describe(e))}"
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
        return [f"unreadable timestamp: {esc(str(e))}"]
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
                problems.append(f"outcome_evidence.{esc(outcome)} cites event {seq}, but the trace has only {count} events")
    return problems


def quote_refs(event):
    """The quote ids an event refers to, by event type. quote_received defines ids; it does not refer to them."""
    p, kind = event["payload"], event["type"]
    if kind in ("requirement_check", "selection_made", "action_executed"):
        return [p["quote_id"]]
    if kind == "human_confirmation" and "quote_id" in p:
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
                problems.append(f"event {seq} (quote_received): quote_id '{esc(qid)}' was already used by event {received[qid]}")
            else:
                received[qid] = seq
        for qid in quote_refs(ev):
            if qid not in received:
                problems.append(f"event {seq} ({esc(kind)}): refers to quote '{esc(qid)}', but no earlier quote_received offered it")
    return problems


NOTE_AGENTS_CLAIM = "the principal's approvals are recorded by the agent; the principal did not sign the seal"


def policy_not_applied(setting):
    return ("the policy that only principal-signed approvals count was not applied, "
            f"because human_confirmation is '{esc(setting)}'")


def confirmation_problems(mandate, trace, signed=None, require=False, seal_signed=False):
    """Every binding action needs its own live yes from the principal, given
    after the agent chose what to buy and for the quote it chose.

    Applies when the mandate says human_confirmation is "always". A yes only
    counts if it comes from the principal with decision "approved", after a
    selection_made. It is used up by one action_executed, and that action must
    be on the quote that was selected. A new selection_made cancels it, because
    a yes to one choice is not a yes to a different one; so does a later
    human_confirmation that is declined or modified.

    signed maps the seq of each human_confirmation whose principal signature
    verified to its confirmation_ref. A signed yes is for the quote, amount and
    AER it signed; with require, an unsigned yes does not count at all.

    "above_limits" needs the price and scope rules, so it waits for Phase 3.

    Returns (problems, notes). A note says what the check could not establish,
    as Go's NotChecked does; only the two about the principal's approvals are
    reported here.
    """
    signed = signed or {}
    setting = mandate["human_confirmation"]
    if setting != "always":
        return [], ([policy_not_applied(setting)] if require and setting in ("above_limits", "never") else [])
    problems = []
    selected = None        # quote_id of the latest selection_made
    pending = False        # an approval is waiting to be used by an action
    ignored = False        # an unsigned approval was set aside, because only signed ones count
    approved_quote = None
    approved_signed = False
    approved_amount = None  # of a signed approval
    offered = {}           # quote_id -> the AER the quote offered, if it offered one
    principal_approvals = signed_approvals = 0
    for ev in trace["events"]:
        kind, payload, seq = ev["type"], ev["payload"], ev["seq"]
        if kind == "quote_received":
            if "aer" in payload:
                offered[payload["quote_id"]] = payload["aer"]
        elif kind == "selection_made":
            selected = payload["quote_id"]
            pending = ignored = False
        elif kind == "human_confirmation":
            if payload["decision"] == "approved":
                is_signed = seq in signed
                if ev["actor"] == "principal":
                    principal_approvals += 1
                    signed_approvals += is_signed
                # Before any selection_made, selected is None: the yes is for no choice, so no yes is pending.
                if ev["actor"] != "principal" or selected is None:
                    pass
                elif is_signed:
                    quote = payload["quote_id"]
                    pending, approved_quote, approved_signed, approved_amount = True, quote, True, payload["amount"]
                    if "aer" in payload and offered.get(quote) != payload["aer"]:
                        shown = esc(offered[quote]) if quote in offered else "no AER"
                        problems.append(
                            f"event {seq} (human_confirmation): the principal approved an AER of {esc(payload['aer'])} "
                            f"on quote '{esc(quote)}', but that quote offers {shown}"
                        )
                elif require:
                    ignored = True  # pending is left as it was
                else:
                    pending, approved_quote, approved_signed = True, selected, False
            else:
                pending = ignored = False
        elif kind == "action_executed":
            amount = payload["amount_committed"]
            committed = f"{esc(amount['amount'])} {esc(amount['currency'])}"
            if not pending and ignored:
                problems.append(
                    f"event {seq} (action_executed): the agent committed {committed} "
                    f"on an approval the principal did not sign, but this verifier counts only approvals the principal signed"
                )
            elif not pending:
                problems.append(
                    f"event {seq} (action_executed): the agent committed {committed} "
                    f"without an approved human_confirmation from the principal, but the mandate requires one every time"
                )
            elif payload["quote_id"] != approved_quote:
                problems.append(
                    f"event {seq} (action_executed): the agent committed {committed} "
                    f"on quote '{esc(payload['quote_id'])}', but the principal approved quote '{esc(approved_quote)}'"
                )
            elif approved_quote != selected:
                # A signed yes for a quote other than the latest selection does not cover the selected one.
                problems.append(
                    f"event {seq} (action_executed): the agent committed {committed} "
                    f"on quote '{esc(payload['quote_id'])}', but the principal approved quote '{esc(selected)}'"
                )
            if pending and approved_signed and (amount["amount"], amount["currency"]) != (approved_amount["amount"], approved_amount["currency"]):
                problems.append(
                    f"event {seq} (action_executed): the agent committed {committed}, "
                    f"but the principal approved {esc(approved_amount['amount'])} {esc(approved_amount['currency'])}"
                )
            pending = ignored = approved_signed = False
    all_signed = principal_approvals > 0 and signed_approvals == principal_approvals
    notes = []
    if not problems and not seal_signed and not require and not all_signed:
        notes.append(NOTE_AGENTS_CLAIM)
    return problems, notes


def fail(problems, headline=""):
    print(f"FAIL  {esc(headline)}" if headline else "FAIL")
    for p in problems:
        print("  -", esc(p))
    return 1


def print_notes(notes):
    for n in notes:
        print("  note:", esc(n))


def _must_escape(o):
    return (o < 0x20 or 0x7F <= o <= 0x9F or o in (0x2028, 0x2029, 0x200E, 0x200F)
            or 0x202A <= o <= 0x202E or 0x2066 <= o <= 0x2069 or 0xD800 <= o <= 0xDFFF)


def esc(s):
    """A document-supplied string, safe to print inside a message: plain printable text is kept;
    these become \\uXXXX (lower case hex): control characters (C0, DEL, C1), U+2028 and U+2029,
    the bidirectional controls U+200E, U+200F, U+202A-U+202E and U+2066-U+2069, and lone
    surrogates (U+D800-U+DFFF, which Go strings cannot hold).
    witness/internal/text (Go, Esc) does the same, so both print the same bytes. Escaping twice
    changes nothing, because a backslash is kept as it is."""
    return "".join(f"\\u{ord(c):04x}" if _must_escape(ord(c)) else c for c in s)


def spki(key):
    """A public key's bytes (DER SubjectPublicKeyInfo), to tell whether two key ids name the same key."""
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


CONFIRMATION_REQUIRED = ("shown_summary_hash", "quote_id", "amount")


def signature_problems(mandate, trace, principal, provider, agent, require_principal_seal=False):
    """SPEC.md rule 15, in the order the Go verifier (witness/rule15.go) checks it.

    principal, provider and agent map key ids to public keys: the keys trusted for
    each role. Checked against the principal and provider files: the mandate
    signer's key id, the mandate's agent.public_key_ref and each provider
    signature's key id. Key material is compared between the mandate signer, the
    agent key and each provider signature. Not checked: a key id listed in the
    agent file against the provider file, or the same key or key id listed in two
    role files in any other way. Keep the role files disjoint. The agent's keys are consulted only for the key the mandate names, and
    only once the principal's signature on the mandate has verified.

    1. The mandate signature's key is a principal key, not also a provider key, and verifies.
    2. If not, stop: the seal signatures are not checked.
    3. The mandate names an agent key that the agent keys hold, that is neither a
       principal nor a provider key, and is not the key that signed the mandate.
    4. Each seal signature suits its role: the agent's uses exactly that key; the
       provider's a provider key (and nothing else); the principal's the key that
       signed the mandate; any other signer is refused.
    5. The seal has a valid agent signature and a valid provider signature, and
       a principal one if require_principal_seal.
    6. Each human_confirmation that carries a principal_signature, in event order:
       its actor is the principal; it holds the fields a signed confirmation needs;
       the signature uses the key that signed the mandate; and it verifies over
       jws.confirmation_payload. Runs whenever step 2 did not stop.

    Returns (problems, principal_signed, signed): whether the seal carries a valid
    principal signature, and a dict from the seq of each human_confirmation whose
    signature verified to its confirmation_ref.
    """
    problems = []

    def verifies(sig, where, typ, payload, key):
        try:
            jws.verify(sig["value"], payload, key, sig["alg"], sig["key_id"], typ)
            return True
        except ValueError as e:
            problems.append(f"{where} does not verify: {esc(str(e))}")
            return False

    msig = mandate["signature"]
    p = msig["key_id"]
    principal_key = principal.get(p)
    if principal_key is None:
        problems.append(f"mandate signature: key '{esc(p)}' is not trusted for the principal")
    else:
        if p in provider:
            problems.append(f"mandate signature: key '{esc(p)}' is also trusted for the provider")
        verifies(msig, "mandate signature", jws.MANDATE_TYP, jws.mandate_payload(mandate), principal_key)
    if problems:
        problems.append("seal signatures were not checked, because the mandate signature is not valid")
        return problems, False, {}

    agent_ref = mandate["agent"].get("public_key_ref")
    agent_key = None
    agent_usable = False
    if not agent_ref:
        problems.append("the mandate names no agent key (agent.public_key_ref)")
    else:
        agent_usable = True
        for role, keys in (("principal", principal), ("provider", provider)):
            if agent_ref in keys:
                problems.append(f"the agent's key '{esc(agent_ref)}' is also trusted for the {role}")
                agent_usable = False
        agent_key = agent.get(agent_ref)
        if agent_key is None:
            problems.append(f"the agent's key '{esc(agent_ref)}' could not be found")
            agent_usable = False
        elif spki(agent_key) == spki(principal_key):
            problems.append(f"the agent's key '{esc(agent_ref)}' is the key that signed the mandate")
            agent_usable = False

    payload = jws.seal_payload(trace)
    agent_signed = provider_signed = principal_signed = False
    for i, sig in enumerate(trace["seal"]["signatures"]):
        signer, key_id = sig["signer"], sig["key_id"]
        where = f"seal signature {i} ({esc(signer)})"
        if signer == "agent":
            if agent_ref and key_id != agent_ref:
                problems.append(f"seal signature {i} (agent) uses key '{esc(key_id)}', but the mandate names the agent's key as '{esc(agent_ref)}'")
                continue
            if agent_usable and verifies(sig, where, jws.SEAL_TYP, payload, agent_key):
                agent_signed = True
        elif signer == "provider":
            key = provider.get(key_id)
            if key is None:
                problems.append(f"seal signature {i} (provider): key '{esc(key_id)}' is not trusted for the provider")
            elif key_id in principal:
                problems.append(f"seal signature {i} (provider): key '{esc(key_id)}' is also trusted for the principal")
            elif agent_key is not None and spki(key) == spki(agent_key):
                problems.append(f"seal signature {i} (provider) uses the same key as the agent")
            elif spki(key) == spki(principal_key):
                problems.append(f"seal signature {i} (provider) uses the same key as the mandate signature")
            elif verifies(sig, where, jws.SEAL_TYP, payload, key):
                provider_signed = True
        elif signer == "principal":
            if key_id != p:
                problems.append(f"seal signature {i} (principal) uses key '{esc(key_id)}', but the mandate was signed with '{esc(p)}'")
            elif verifies(sig, where, jws.SEAL_TYP, payload, principal_key):
                principal_signed = True
        else:
            problems.append(f"seal signature {i} ({esc(signer)}): this verifier trusts no keys for that signer")

    if not agent_signed:
        problems.append("the seal has no valid signature from the agent the mandate names")
    if not provider_signed:
        problems.append("the seal has no valid signature from a provider")
    if require_principal_seal and not principal_signed:
        problems.append("the seal has no valid signature from the principal who signed the mandate")

    signed = {}
    previous = ""  # the confirmation_ref of the latest signed confirmation before this one
    for i, ev in enumerate(trace["events"]):
        pl = ev["payload"]
        if ev["type"] != "human_confirmation" or "principal_signature" not in pl:
            continue
        csig = pl["principal_signature"]
        body = jws.confirmation_payload(trace["trace_id"], trace["mandate_ref"]["mandate_hash"], previous, pl)
        ref = jws.confirmation_ref(body)
        previous = ref  # advanced for every signed event, verified or not
        label = f"event {i} (human_confirmation)"
        refused = False
        if ev["actor"] != "principal":
            problems.append(f"{label}: carries the principal's signature, but its actor is '{esc(ev['actor'])}'")
            refused = True
        for name in CONFIRMATION_REQUIRED:
            if name not in pl:
                problems.append(f"{label}: a signed confirmation needs {name}")
                refused = True
        if refused:
            continue
        if csig["key_id"] != p:
            problems.append(f"{label}: principal_signature uses key '{esc(csig['key_id'])}', but the mandate was signed with '{esc(p)}'")
            continue
        if verifies(csig, f"{label}: principal_signature", jws.CONFIRMATION_TYP, body, principal_key):
            signed[i] = ref
    return problems, principal_signed, signed


class Parser(argparse.ArgumentParser):
    def error(self, message):
        print(f"validate.py: {message}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        raise SystemExit(2)


USAGE = """usage: python scripts/validate.py <name>.mandate.json <name>.trace.json KEYS
KEYS is one of:
  --principal-keys F --provider-keys F --agent-keys F [--require-principal-seal] [--require-signed-confirmations]
      F is a JWKS file (plain JSON Web Key Set) of the keys trusted for that role.
      --require-signed-confirmations: only approvals the principal signed count (rule 9)
  --skip-signatures
      leave out the signature checks; the result is then never a PASS"""

KEY_FLAGS = (("principal_keys", "--principal-keys"), ("provider_keys", "--provider-keys"), ("agent_keys", "--agent-keys"))


def parse_args(argv):
    parser = Parser(prog="validate.py", usage=USAGE, allow_abbrev=False)
    parser.add_argument("mandate")
    parser.add_argument("trace")
    for dest, flag in KEY_FLAGS:
        parser.add_argument(flag, dest=dest)
    parser.add_argument("--require-principal-seal", action="store_true")
    parser.add_argument("--require-signed-confirmations", action="store_true")
    parser.add_argument("--skip-signatures", action="store_true")
    parser.add_argument("--keys", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    given = [flag for dest, flag in KEY_FLAGS if getattr(args, dest)]
    if args.keys:
        parser.error("--keys is gone: one key file cannot say which key is trusted for which party. "
                     "Give --principal-keys, --provider-keys and --agent-keys, one JWKS file for each role")
    if args.skip_signatures and (given or args.require_principal_seal or args.require_signed_confirmations):
        parser.error("--skip-signatures cannot be combined with key files, --require-principal-seal or --require-signed-confirmations")
    if not args.skip_signatures and len(given) != len(KEY_FLAGS):
        parser.error("signatures are checked with all of --principal-keys, --provider-keys and --agent-keys "
                     "(or leave them out explicitly with --skip-signatures)")
    return args


def run(argv):
    args = parse_args(argv)
    mandate_path, trace_path = args.mandate, args.trace

    try:
        mandate, trace = load(mandate_path), load(trace_path)
    except Unreadable as e:
        return fail([str(e)], "the record is malformed")
    keys = {}
    if not args.skip_signatures:
        for dest, flag in KEY_FLAGS:
            path = getattr(args, dest)
            try:
                keys[dest] = jws.load_jwks(path)
            except (OSError, ValueError, KeyError) as e:
                return fail([f"{path}: cannot read the key file ({e})"])

    name = Path(trace_path).name

    problems = [f"mandate {e}" for e in schema_errors(mandate, "mandate.schema.json")]
    problems += [f"trace {e}" for e in schema_errors(trace, "trace.schema.json")]
    if problems:
        return fail(problems, f"{name}: the record is malformed")

    problems = (chain_problems(mandate, trace) + time_problems(trace)
                + evidence_problems(trace) + reference_problems(trace))
    principal_signed, signed = False, {}
    if not args.skip_signatures:
        sig_problems, principal_signed, signed = signature_problems(
            mandate, trace, keys["principal_keys"], keys["provider_keys"], keys["agent_keys"], args.require_principal_seal)
        problems += sig_problems
    if problems:
        return fail(problems, f"{name}: the record is broken or has been tampered with")

    problems, notes = confirmation_problems(mandate, trace, signed, args.require_signed_confirmations, principal_signed)
    if problems:
        return fail(problems, f"{name}: the record is intact, but the agent broke its mandate")

    setting = mandate["human_confirmation"]
    confirmation = "confirmation rule met" if setting == "always" else f"confirmation rule not checked for '{setting}' yet"
    signatures = "signatures NOT checked (--skip-signatures)" if args.skip_signatures else "signatures valid"
    summary = f"schema ok, {len(trace['events'])} events chained to mandate, seal covers final event, {signatures}, {confirmation}"
    if args.skip_signatures:
        status = fail([summary], f"{name}: signatures were not checked (--skip-signatures), so this is not a pass")
        print_notes(notes)
        return status
    print(f"PASS  {esc(name)}: {summary}")
    for seq, ref in signed.items():
        print(f"  signed: event {seq} (human_confirmation): signed by the principal, confirmation_ref {ref}")
    print_notes(notes)
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
