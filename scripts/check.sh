#!/usr/bin/env bash
# Everything CI runs. Usage: scripts/check.sh  (set PYTHON to override the interpreter)
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
M=examples/home-insurance-switch.mandate.json
T=examples/home-insurance-switch.trace.json
KEYS=(--principal-keys examples/keys.principal.jwks.json --provider-keys examples/keys.provider.jwks.json
      --agent-keys examples/keys.agent.jwks.json)  # the examples' public keys, one file per role
SKIP=(--skip-signatures)  # for inputs that fail before, or regardless of, their signatures
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# expect_fail <label> <expected text> <validate.py args...>
# Passes only if the validator exits 1 with a clean FAIL report naming the problem.
expect_fail() {
  local label="$1" want="$2"; shift 2
  local out code=0
  out="$("$PY" scripts/validate.py "$@" 2>&1)" || code=$?
  if [[ $code -ne 1 || "$out" != FAIL* || "$out" != *"$want"* ]]; then
    echo "not ok  $label (exit $code)"; echo "$out"; exit 1
  fi
  echo "ok      $label"
}

echo "== examples are reproducible from scripts/make_examples.py"
"$PY" scripts/make_examples.py >/dev/null
git diff --exit-code -- examples/
echo "ok      examples match the generator"

echo "== test vectors are reproducible from their generators"
"$PY" scripts/make_vectors.py >/dev/null
node scripts/make_number_vectors.mjs >/dev/null
git diff --exit-code -- testdata/vectors/
echo "ok      vectors match the generators"

echo "== the Python implementation agrees with JavaScript on number formatting"
"$PY" - <<'EOF'
import json, struct, sys
sys.path.insert(0, "scripts")
from chain import canon
vectors = json.load(open("testdata/vectors/numbers.json"))["vectors"]
wrong = [v for v in vectors if canon(struct.unpack(">d", bytes.fromhex(v["bits"]))[0]).decode() != v["output"]]
for v in wrong[:5]:
    print("  ", v["bits"], "wanted", v["output"])
sys.exit(f"not ok  {len(wrong)} of {len(vectors)} numbers differ" if wrong else print(f"ok      all {len(vectors)} numbers match"))
EOF

echo "== the Python implementation agrees with every signature vector"
"$PY" - <<'EOF'
import json, sys
sys.path.insert(0, "scripts")
import jws
vectors = json.load(open("testdata/vectors/signatures.json"))["vectors"]
wrong = []
for v in vectors:
    try:
        jws.verify(v["jws"], v["payload"].encode(), jws.load_jwk(v["jwk"]), v["alg"], v["kid"], v["typ"])
        got, why = True, ""
    except ValueError as e:
        got, why = False, str(e)
    if got != v["valid"]:
        wrong.append(v)
        print("  ", v["name"], "wanted valid =", v["valid"], why)
sys.exit(f"not ok  {len(wrong)} of {len(vectors)} signature vectors differ" if wrong else print(f"ok      all {len(vectors)} signature vectors match"))
EOF

echo "== hostile JWS headers are refused promptly and cleanly"
"$PY" - <<'EOF'
import sys, time
sys.path.insert(0, "scripts")
import jws
key = jws.example_key("vector ed25519").public_key()

def refuse(label, header, bound):
    token = f"{jws.b64(header)}..{jws.b64(bytes(64))}"
    start = time.monotonic()
    try:
        jws.verify(token, b"{}", key, "EdDSA", "k", "t")
    except ValueError as e:
        took = time.monotonic() - start
        if took > bound:
            sys.exit(f"not ok  {label}: refused, but took {took:.1f}s (limit {bound}s)")
        print(f"ok      {label} ({took:.2f}s): {str(e)[:60]}")
    except BaseException as e:
        sys.exit(f"not ok  {label}: raised {type(e).__name__}, not ValueError")
    else:
        sys.exit(f"not ok  {label}: was accepted")

refuse("50,000 distinct members", b"{" + b",".join(b'"m%d":1' % i for i in range(50000)) + b"}", 2)
refuse("3,000,000-deep nesting", b"[" * 3000000, 10)
EOF

echo "== the passing examples pass"
"$PY" scripts/validate.py "$M" "$T" "${KEYS[@]}"
"$PY" scripts/validate.py examples/fixed-rate-savings-switch.mandate.json examples/fixed-rate-savings-switch.trace.json "${KEYS[@]}"

echo "== the no-confirmation example fails, as a mandate breach rather than a broken record"
expect_fail "purchase without the principal's yes is flagged" \
  "the record is intact, but the agent broke its mandate" \
  examples/home-insurance-no-confirmation.mandate.json examples/home-insurance-no-confirmation.trace.json "${KEYS[@]}"
# The Go verifier (witness.Check) must report the same finding; its test reads this same file.
expect_fail "the rule 9 finding is word for word the one the Go verifier reports" \
  "$(cat testdata/golden/no-confirmation.rule9.txt)" \
  examples/home-insurance-no-confirmation.mandate.json examples/home-insurance-no-confirmation.trace.json "${KEYS[@]}"

echo "== broken inputs fail cleanly"
sed 's/"298.00"/"198.00"/' "$T" > "$TMP/tampered.json"
expect_fail "edited price is detected" "event 2: hash does not match" "$M" "$TMP/tampered.json" "${SKIP[@]}"

"$PY" -c 'import json,sys; t=json.load(open(sys.argv[1])); del t["mandate_ref"]; json.dump(t, open(sys.argv[2], "w"))' "$T" "$TMP/no-ref.json"
expect_fail "schema-invalid trace is reported, not crashed on" "mandate_ref" "$M" "$TMP/no-ref.json" "${SKIP[@]}"

"$PY" -c 'import json,sys; t=json.load(open(sys.argv[1])); del t["events"][2]["payload"]["aer"]; json.dump(t, open(sys.argv[2], "w"))' \
  examples/fixed-rate-savings-switch.trace.json "$TMP/no-rate.json"
expect_fail "quote with neither price nor rate is rejected" "needs at least one of: price, aer" \
  examples/fixed-rate-savings-switch.mandate.json "$TMP/no-rate.json" "${SKIP[@]}"

# Variants whose hash chain is recomputed after the edit, as a forger would,
# so the chain itself is valid. The reference variants are checked with
# --skip-signatures, so that only the reference check can object; the rewrites
# are checked with keys, to show the signatures catch what the chain cannot.
"$PY" - "$T" "$TMP" <<'EOF'
import json, sys
sys.path.insert(0, "scripts")
from chain import event_hash

src, out = sys.argv[1], sys.argv[2]

def variant(name, mutate, trace_mutate=lambda t: None):
    t = json.load(open(src))
    mutate(t["events"])
    trace_mutate(t)
    prev = t["mandate_ref"]["mandate_hash"]
    for ev in t["events"]:
        ev["prev_hash"] = prev
        ev["hash"] = event_hash(ev)
        prev = ev["hash"]
    t["seal"]["final_event_hash"] = prev
    json.dump(t, open(f"{out}/{name}.json", "w"))

variant("dangling-ref", lambda e: e[8]["payload"].update(quote_id="q_nowhere"))
variant("duplicate-quote", lambda e: e[3]["payload"].update(quote_id="q_newco"))
variant("rewritten-price", lambda e: e[2]["payload"]["price"].update(amount="198.00"))

def declined_after_approval(e):
    declined = json.loads(json.dumps(e[9]))
    declined["payload"]["decision"] = "declined"
    e.insert(10, declined)  # the principal says no after saying yes
    for i, ev in enumerate(e):
        ev["seq"] = i

variant("declined-after-approval", declined_after_approval)

def approval_before_selection(e):
    e[8], e[9] = e[9], e[8]  # the principal says yes, and only then does the agent choose
    e[8]["at"], e[9]["at"] = e[9]["at"], e[8]["at"]
    for i, ev in enumerate(e):
        ev["seq"] = i

variant("approval-before-selection", approval_before_selection)


def approval_without_selection(e):
    del e[8]  # a yes with no choice anywhere before the purchase
    for i, ev in enumerate(e):
        ev["seq"] = i

variant("approval-without-selection", approval_without_selection,
        lambda t: [r.update(event_seqs=sorted({min(x, len(t["events"]) - 1) for x in r["event_seqs"]}))
                   for r in t["outcome_evidence"].values()])  # keep the evidence citing events that exist
variant("agent-approval", lambda e: e[9].update(actor="agent"))  # the agent writes the yes itself
variant("different-quote", lambda e: e[10]["payload"].update(quote_id="q_cheapco"))  # approved q_newco
variant("status-changed", lambda e: None, lambda t: t["journey"].update(status="failed"))
EOF
expect_fail "selection of a quote nobody offered is caught" \
  "event 8 (selection_made): refers to quote 'q_nowhere', but no earlier quote_received offered it" "$M" "$TMP/dangling-ref.json" "${SKIP[@]}"
expect_fail "two quotes sharing an id is caught" \
  "event 3 (quote_received): quote_id 'q_newco' was already used by event 2" "$M" "$TMP/duplicate-quote.json" "${SKIP[@]}"

expect_fail "a yes withdrawn before the purchase is flagged as a mandate breach" \
  "the record is intact, but the agent broke its mandate" "$M" "$TMP/declined-after-approval.json" "${SKIP[@]}"
expect_fail "a declined yes leaves the purchase without an approval" \
  "event 11 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal" "$M" "$TMP/declined-after-approval.json" "${SKIP[@]}"
expect_fail "a yes given before the choice was made does not cover the purchase" \
  "event 10 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal" "$M" "$TMP/approval-before-selection.json" "${SKIP[@]}"
expect_fail "a yes with no choice made at all is not an approval of the purchase" \
  "event 9 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal" "$M" "$TMP/approval-without-selection.json" "${SKIP[@]}"
expect_fail "a yes given before the choice is still a mandate breach, not a broken record" \
  "the record is intact, but the agent broke its mandate" "$M" "$TMP/approval-before-selection.json" "${SKIP[@]}"
expect_fail "a yes recorded by the agent is not the principal's yes" \
  "event 10 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal" "$M" "$TMP/agent-approval.json" "${SKIP[@]}"
expect_fail "a yes recorded by the agent is a mandate breach, not a broken record" \
  "the record is intact, but the agent broke its mandate" "$M" "$TMP/agent-approval.json" "${SKIP[@]}"
expect_fail "a purchase on a different quote than the one approved is flagged as a mandate breach" \
  "the record is intact, but the agent broke its mandate" "$M" "$TMP/different-quote.json" "${SKIP[@]}"
expect_fail "the quote approved is named in the finding" \
  "on quote 'q_cheapco', but the principal approved quote 'q_newco'" "$M" "$TMP/different-quote.json" "${SKIP[@]}"

expect_fail "a re-hashed rewrite is caught by the seal signatures" \
  "seal signature 0 (agent) does not verify" "$M" "$TMP/rewritten-price.json" "${KEYS[@]}"
expect_fail "a changed journey status is caught, because the seal covers the whole trace" \
  "seal signature 1 (provider) does not verify" "$M" "$TMP/status-changed.json" "${KEYS[@]}"
"$PY" -c 'import json,sys; m=json.load(open(sys.argv[1])); m["limits"]["max_transactions"]=5; json.dump(m, open(sys.argv[2], "w"))' "$M" "$TMP/mandate-edited.json"
expect_fail "an edited mandate is caught by the principal's signature" \
  "mandate signature does not verify" "$TMP/mandate-edited.json" "$T" "${KEYS[@]}"
echo '{"keys": []}' > "$TMP/no-keys.jwks.json"
expect_fail "a mandate key missing from the principal key file is reported" \
  "is not trusted for the principal" "$M" "$T" \
  --principal-keys "$TMP/no-keys.jwks.json" --provider-keys examples/keys.provider.jwks.json --agent-keys examples/keys.agent.jwks.json

echo "== rule 15: keys are bound to roles, and the seal needs the agent and a provider"
# Forged variants of the home-insurance example, built with the same signing code as make_examples.py.
"$PY" - "$M" "$T" "$TMP" <<'EOF'
import copy, json, sys
sys.path.insert(0, "scripts")
import jws
from chain import event_hash, mandate_hash
from make_examples import KEY_IDS

mandate_path, trace_path, out = sys.argv[1:4]
mandate, trace = json.load(open(mandate_path)), json.load(open(trace_path))


def dump(name, doc):
    json.dump(doc, open(f"{out}/{name}.json", "w"))


def rechain(t):
    prev = t["mandate_ref"]["mandate_hash"]
    for ev in t["events"]:
        ev["prev_hash"] = prev
        ev["hash"] = event_hash(ev)
        prev = ev["hash"]
    t["seal"]["final_event_hash"] = prev


def sign_mandate(m, holder):
    kid = KEY_IDS[holder]
    m["signature"] = {"alg": "EdDSA", "key_id": kid,
                      "value": jws.sign(jws.example_key(holder), "EdDSA", kid, jws.MANDATE_TYP, jws.mandate_payload(m))}


def resign_confirmation(t):
    """Sam signs his yes again: the signature covers the mandate hash, which these variants change."""
    pl = t["events"][9]["payload"]
    pl.pop("principal_signature", None)
    body = jws.confirmation_payload(t["trace_id"], t["mandate_ref"]["mandate_hash"], "", pl)
    kid = KEY_IDS["sam"]
    pl["principal_signature"] = {"alg": "EdDSA", "key_id": kid,
                                 "value": jws.sign(jws.example_key("sam"), "EdDSA", kid, jws.CONFIRMATION_TYP, body)}


def seal(t, *signers):
    """Replace the seal's signatures with these (holder, role) or (holder, role, key_id) signers."""
    payload = jws.seal_payload(t)
    sigs = []
    for holder, role, *kid in signers:
        kid = kid[0] if kid else KEY_IDS[holder]
        sigs.append({"signer": role, "alg": "EdDSA", "key_id": kid,
                     "value": jws.sign(jws.example_key(holder), "EdDSA", kid, jws.SEAL_TYP, payload)})
    t["seal"]["signatures"] = sigs
    return t


AGENT, PROVIDER = ("home-helper", "agent"), ("newco", "provider")


def variant(*signers, change=lambda t: None):
    t = copy.deepcopy(trace)
    change(t)
    return seal(t, *signers)


# The attack: change what was committed, re-hash, and seal with the agent's key alone.
def rewrite(t):
    t["events"][10]["payload"]["amount_committed"]["amount"] = "198.00"
    rechain(t)


dump("agent-only-rewrite", variant(AGENT, change=rewrite))
dump("no-provider-signature", variant(AGENT))
dump("provider-label-agent-key", variant(AGENT, ("home-helper", "provider")))
dump("provider-label-principal-key", variant(AGENT, ("sam", "provider")))
dump("witness-service", variant(AGENT, PROVIDER, ("newco", "witness_service")))
dump("jo-as-principal", variant(AGENT, PROVIDER, ("jo", "principal")))
dump("sam-cosigned", variant(AGENT, PROVIDER, ("sam", "principal")))

# The agent re-signs the mandate with its own key; the signature is outside the mandate hash.
m = copy.deepcopy(mandate)
sign_mandate(m, "home-helper")
dump("mandate-agent-key", m)

# A mandate that names no agent key. Signed by the principal and chained again, with Sam's yes signed again
# for the new mandate hash, so only M5 objects.
m = copy.deepcopy(mandate)
del m["agent"]["public_key_ref"]
sign_mandate(m, "sam")
dump("no-ref.mandate", m)
t = copy.deepcopy(trace)
t["mandate_ref"]["mandate_hash"] = mandate_hash(m)
resign_confirmation(t)
rechain(t)
dump("no-ref.trace", seal(t, AGENT, PROVIDER))

# The provider key file with the agent's key added: one key trusted for two roles.
keys = json.load(open("examples/keys.provider.jwks.json"))
keys["keys"].append(jws.public_jwk(jws.example_key("home-helper").public_key(), KEY_IDS["home-helper"]))
dump("provider-with-agent.jwks", keys)

# A key id with a line break and a forged PASS line in it must not reach the report raw.
dump("control-char-key-id", variant(AGENT, ("newco", "provider", "k\nPASS  forged\u2028")))


def keyfile(name, *extra, base="provider"):
    """A role's key file with extra (holder, key_id) keys added."""
    doc = json.load(open(f"examples/keys.{base}.jwks.json"))
    doc["keys"] += [jws.public_jwk(jws.example_key(h).public_key(), kid) for h, kid in extra]
    dump(name, doc)


ALIAS = "https://alias.example/jwks.json#alias"
# One combined key file used for every role: the mandate signer is also trusted for the provider (M2).
combined = {"keys": []}
for role in ("principal", "agent", "provider"):
    combined["keys"] += json.load(open(f"examples/keys.{role}.jwks.json"))["keys"]
dump("all-roles.jwks", combined)
# A principal file that also holds a provider's key (S2).
keyfile("principal-with-provider.jwks", ("newco", KEY_IDS["newco"]), base="principal")
# The agent's key bytes, and the mandate signer's, under a second id in the provider file (S3).
keyfile("provider-with-aliases.jwks", ("home-helper", ALIAS), ("sam", ALIAS + "2"))
dump("provider-same-key-as-agent", variant(AGENT, ("home-helper", "provider", ALIAS)))
dump("provider-same-key-as-mandate-signer", variant(AGENT, ("sam", "provider", ALIAS + "2")))
# A mandate whose agent key is the principal's key under another id (M8).
m = copy.deepcopy(mandate)
m["agent"]["public_key_ref"] = ALIAS
sign_mandate(m, "sam")
dump("agent-is-signer.mandate", m)
t = copy.deepcopy(trace)
t["mandate_ref"]["mandate_hash"] = mandate_hash(m)
resign_confirmation(t)
rechain(t)
dump("agent-is-signer.trace", seal(t, AGENT, PROVIDER))
keyfile("agent-alias.jwks", ("sam", ALIAS), base="agent")
keyfile("principal-with-agent.jwks", ("home-helper", KEY_IDS["home-helper"]), base="principal")

# Document strings reach every message escaped, not only rule 15's.
t = copy.deepcopy(trace)
t["events"][4]["payload"]["quote_id"] = "q\nPASS  forged"
rechain(t)
dump("forged-quote-id", t)
# C1, bidirectional and C0 characters in a key id (the Go test reads the same golden file).
KINDS = "a" + chr(0x85) + "b" + chr(0x202E) + "c" + chr(0x2066) + "d" + chr(0x200F) + "e\x01"
dump("esc-kinds-key-id", variant(AGENT, ("newco", "provider", KINDS)))
# A lone surrogate (a JSON escape for U+D800) in a key id, and a file that is not UTF-8.
t = variant(AGENT, PROVIDER)
t["seal"]["signatures"][1]["key_id"] = "k" + chr(0xD800) + "x"  # cannot be signed: set after
dump("lone-surrogate", t)
open(f"{out}/not-utf8.json", "wb").write(b'{"spec_version": "0.1", "x": "\xff\xfe"}')
# A mandate that repeats agent.public_key_ref: the first names a key the verifier never sees.
text = open(mandate_path).read()
ref = '"public_key_ref": "' + KEY_IDS["home-helper"] + '"'
assert text.count(ref) == 1
open(f"{out}/duplicate-key.mandate.json", "w").write(
    text.replace(ref, '"public_key_ref": "https://evil.example/j.json#x",\n      ' + ref))
EOF
AGENT_KEY="https://agent.example/.well-known/jwks.json#home-helper"  # the key the mandate names
# The attack this closes: rewrite what was committed, re-hash, seal with the agent's key alone.
# The Go verifier reports the same line; its test reads this same file.
expect_fail "an agent-only rewrite is refused: no provider signature" \
  "$(cat testdata/golden/rule15.no-provider.txt)" "$M" "$TMP/agent-only-rewrite.json" "${KEYS[@]}"
expect_fail "a seal with no provider signature is refused" \
  "the seal has no valid signature from a provider" "$M" "$TMP/no-provider-signature.json" "${KEYS[@]}"
expect_fail "the agent re-signing the mandate with its own key is refused, word for word as Go does" \
  "$(cat testdata/golden/rule15.mandate-agent-key.txt)" "$TMP/mandate-agent-key.json" "$T" "${KEYS[@]}"
expect_fail "seal signatures are not checked once the mandate signature is refused" \
  "seal signatures were not checked, because the mandate signature is not valid" "$TMP/mandate-agent-key.json" "$T" "${KEYS[@]}"
expect_fail "the agent's key labelled provider is refused" \
  "seal signature 1 (provider): key '$AGENT_KEY' is not trusted for the provider" "$M" "$TMP/provider-label-agent-key.json" "${KEYS[@]}"
expect_fail "a principal's key labelled provider is refused" \
  "(provider): key 'https://wallet.example/.well-known/jwks.json#prn_a91f0c3e' is not trusted for the provider" \
  "$M" "$TMP/provider-label-principal-key.json" "${KEYS[@]}"
expect_fail "the agent's key trusted for the provider as well is refused" \
  "the agent's key '$AGENT_KEY' is also trusted for the provider" "$M" "$T" \
  --principal-keys examples/keys.principal.jwks.json --provider-keys "$TMP/provider-with-agent.jwks.json" --agent-keys examples/keys.agent.jwks.json
expect_fail "a mandate that names no agent key is refused" \
  "the mandate names no agent key (agent.public_key_ref)" "$TMP/no-ref.mandate.json" "$TMP/no-ref.trace.json" "${KEYS[@]}"
expect_fail "a witness_service signature is refused: no keys are trusted for that signer" \
  "seal signature 2 (witness_service): this verifier trusts no keys for that signer" "$M" "$TMP/witness-service.json" "${KEYS[@]}"
expect_fail "a different principal signing the seal is refused" \
  "seal signature 2 (principal) uses key 'https://wallet.example/.well-known/jwks.json#prn_5d2e7b14', but the mandate was signed with 'https://wallet.example/.well-known/jwks.json#prn_a91f0c3e'" \
  "$M" "$TMP/jo-as-principal.json" "${KEYS[@]}"
expect_fail "--require-principal-seal refuses a seal the principal did not sign" \
  "the seal has no valid signature from the principal who signed the mandate" "$M" "$T" "${KEYS[@]}" --require-principal-seal
"$PY" scripts/validate.py "$M" "$TMP/sam-cosigned.json" "${KEYS[@]}" --require-principal-seal
echo "ok      --require-principal-seal passes a seal the principal co-signed"
expect_fail "--skip-signatures on a genuine record is never a pass" \
  "signatures were not checked (--skip-signatures), so this is not a pass" "$M" "$T" "${SKIP[@]}"

# Each rule 15 message below is compared as a whole line of the report, so removing any one check
# from validate.py (or changing its words) fails this script. The Go tests read the same words.
expect_line() {
  local label="$1" want="$2"; shift 2
  local out code=0
  out="$("$PY" scripts/validate.py "$@" 2>&1)" || code=$?
  if [[ $code -ne 1 || "$out" != FAIL* ]] || ! grep -qxF -- "  - $want" <<<"$out"; then
    echo "not ok  $label (exit $code)"; echo "$out"; exit 1
  fi
  echo "ok      $label"
}
SAM="https://wallet.example/.well-known/jwks.json#prn_a91f0c3e"
NEWCO="https://newco.example/.well-known/jwks.json#seal-2026"
ALIAS="https://alias.example/jwks.json#alias"
expect_line "one key file used for every role: the mandate signer is also a provider key (M2)" \
  "mandate signature: key '$SAM' is also trusted for the provider" "$M" "$T" \
  --principal-keys "$TMP/all-roles.jwks.json" --provider-keys "$TMP/all-roles.jwks.json" --agent-keys "$TMP/all-roles.jwks.json"
expect_line "the agent's key in the provider file is refused (M7)" \
  "the agent's key '$AGENT_KEY' is also trusted for the provider" "$M" "$T" \
  --principal-keys examples/keys.principal.jwks.json --provider-keys "$TMP/provider-with-agent.jwks.json" --agent-keys examples/keys.agent.jwks.json
expect_line "the agent's key in the principal file is refused (M7)" \
  "the agent's key '$AGENT_KEY' is also trusted for the principal" "$M" "$T" \
  --principal-keys "$TMP/principal-with-agent.jwks.json" --provider-keys examples/keys.provider.jwks.json --agent-keys examples/keys.agent.jwks.json
expect_line "a mandate that names no agent key (M5)" \
  "the mandate names no agent key (agent.public_key_ref)" "$TMP/no-ref.mandate.json" "$TMP/no-ref.trace.json" "${KEYS[@]}"
expect_line "an agent key that is the mandate signer's key under another id (M8)" \
  "the agent's key '$ALIAS' is the key that signed the mandate" \
  "$TMP/agent-is-signer.mandate.json" "$TMP/agent-is-signer.trace.json" \
  --principal-keys examples/keys.principal.jwks.json --provider-keys examples/keys.provider.jwks.json --agent-keys "$TMP/agent-alias.jwks.json"
expect_line "a provider key also in the principal file (S2)" \
  "seal signature 1 (provider): key '$NEWCO' is also trusted for the principal" "$M" "$T" \
  --principal-keys "$TMP/principal-with-provider.jwks.json" --provider-keys examples/keys.provider.jwks.json --agent-keys examples/keys.agent.jwks.json
expect_line "a provider signature made with the agent's key bytes under another id (S3, agent)" \
  "seal signature 1 (provider) uses the same key as the agent" "$M" "$TMP/provider-same-key-as-agent.json" \
  --principal-keys examples/keys.principal.jwks.json --provider-keys "$TMP/provider-with-aliases.jwks.json" --agent-keys examples/keys.agent.jwks.json
expect_line "a provider signature made with the mandate signer's key bytes under another id (S3, mandate signature)" \
  "seal signature 1 (provider) uses the same key as the mandate signature" "$M" "$TMP/provider-same-key-as-mandate-signer.json" \
  --principal-keys examples/keys.principal.jwks.json --provider-keys "$TMP/provider-with-aliases.jwks.json" --agent-keys examples/keys.agent.jwks.json

# A key id holding a line break and a forged PASS line is printed escaped, on one line, as the Go verifier does.
expect_line "control characters in a key id are escaped, byte for byte as Go does" \
  "$(cat testdata/golden/rule15.control-chars.txt)" "$M" "$TMP/control-char-key-id.json" "${KEYS[@]}"
out="$("$PY" scripts/validate.py "$M" "$TMP/control-char-key-id.json" "${KEYS[@]}" 2>&1)" || true
if grep -q '^PASS' <<<"$out" || [[ "$(wc -l <<<"$out")" -ne 3 ]]; then
  echo "not ok  a forged PASS line got into the report"; echo "$out"; exit 1
fi
echo "ok      the report has no line a key id could forge"

# Document strings are escaped in every message, not only rule 15's: a quote id holding a line break and a
# forged PASS line stays on one line. The Go tests read the same golden files.
expect_line "a quote id with a forged PASS line is printed escaped, byte for byte as Go does" \
  "$(cat testdata/golden/rule8.forged-quote-id.txt)" "$M" "$TMP/forged-quote-id.json" "${SKIP[@]}"
out="$("$PY" scripts/validate.py "$M" "$TMP/forged-quote-id.json" "${SKIP[@]}" 2>&1)" || true
if grep -q '^PASS' <<<"$out" || [[ "$(wc -l <<<"$out")" -ne 2 ]]; then
  echo "not ok  a forged PASS line got into the report"; echo "$out"; exit 1
fi
echo "ok      no quote id can forge a line of the report"
expect_line "C1, bidirectional and C0 characters in a key id are escaped, byte for byte as Go does" \
  "$(cat testdata/golden/rule15.esc-kinds.txt)" "$M" "$TMP/esc-kinds-key-id.json" "${KEYS[@]}"
expect_fail "a lone surrogate is a clean FAIL, not a traceback" "the record is malformed" "$M" "$TMP/lone-surrogate.json" "${KEYS[@]}"
expect_fail "a lone surrogate is named, not printed" "holds a lone surrogate" "$M" "$TMP/lone-surrogate.json" "${KEYS[@]}"
expect_fail "a file that is not UTF-8 is a clean FAIL, not a traceback" "not valid UTF-8" "$M" "$TMP/not-utf8.json" "${KEYS[@]}"
expect_fail "a duplicate object key is refused, as the Go verifier does" \
  "duplicate object key 'public_key_ref'" "$TMP/duplicate-key.mandate.json" "$T" "${KEYS[@]}"
expect_fail "a duplicate object key makes the record malformed, never a PASS" \
  "the record is malformed" "$TMP/duplicate-key.mandate.json" "$T" "${KEYS[@]}"

# expect_usage <label> <validate.py args...>: exit 2 and a usage message, with nothing checked.
expect_usage() {
  local label="$1"; shift
  local out code=0
  out="$("$PY" scripts/validate.py "$@" 2>&1)" || code=$?
  if [[ $code -ne 2 || "$out" != *"usage:"* ]]; then
    echo "not ok  $label (exit $code)"; echo "$out"; exit 1
  fi
  echo "ok      $label"
}
expect_usage "no key flags is a usage error, not a silent skip" "$M" "$T"
expect_usage "one key flag alone is a usage error" "$M" "$T" --principal-keys examples/keys.principal.jwks.json
expect_usage "two key flags are a usage error" "$M" "$T" --principal-keys examples/keys.principal.jwks.json --provider-keys examples/keys.provider.jwks.json
expect_usage "key files together with --skip-signatures are a usage error" "$M" "$T" "${KEYS[@]}" --skip-signatures
expect_usage "--require-principal-seal without keys is a usage error" "$M" "$T" --require-principal-seal
expect_usage "--require-principal-seal with --skip-signatures is a usage error" "$M" "$T" --skip-signatures --require-principal-seal
expect_usage "the old --keys flag is a usage error" "$M" "$T" --keys examples/keys.principal.jwks.json

echo "== AW-36: the principal signs each human_confirmation, and a verifier can count only those"
POLICY=(--require-signed-confirmations)
SAVINGS_M=examples/fixed-rate-savings-switch.mandate.json
SAVINGS_T=examples/fixed-rate-savings-switch.trace.json

# expect_pass_line <label> <exact line of the report> <validate.py args...>: exit 0, PASS, and the line.
expect_pass_line() {
  local label="$1" want="$2"; shift 2
  local out code=0
  out="$("$PY" scripts/validate.py "$@" 2>&1)" || code=$?
  if [[ $code -ne 0 || "$out" != PASS* ]] || ! grep -qxF -- "$want" <<<"$out"; then
    echo "not ok  $label (exit $code)"; echo "$out"; exit 1
  fi
  echo "ok      $label"
}
# expect_no_line <label> <text no line of the report may contain> <validate.py args...>
expect_no_line() {
  local label="$1" unwanted="$2"; shift 2
  local out code=0
  out="$("$PY" scripts/validate.py "$@" 2>&1)" || code=$?
  if grep -qF -- "$unwanted" <<<"$out"; then
    echo "not ok  $label (exit $code)"; echo "$out"; exit 1
  fi
  echo "ok      $label"
}

# The Go tests (witness/confirm_test.go) read the same golden files.
expect_pass_line "the signed example passes under the policy and prints its signed line, word for word as Go does" \
  "  signed: $(cat testdata/golden/confirmation.signed.txt)" "$M" "$T" "${KEYS[@]}" "${POLICY[@]}"
expect_no_line "a signed yes is not reported as the agent's claim" \
  "$(cat testdata/golden/rule9.agents-claim.txt)" "$M" "$T" "${KEYS[@]}"
expect_pass_line "an unsigned yes still passes without the policy, noted as the agent's claim" \
  "  note: $(cat testdata/golden/rule9.agents-claim.txt)" "$SAVINGS_M" "$SAVINGS_T" "${KEYS[@]}"
expect_line "under the policy an unsigned yes does not cover the purchase (F1), word for word as Go does" \
  "$(cat testdata/golden/rule9.unsigned-under-policy.txt)" "$SAVINGS_M" "$SAVINGS_T" "${KEYS[@]}" "${POLICY[@]}"
expect_line "the no-confirmation example keeps its rule 9 line under the policy" \
  "$(cat testdata/golden/no-confirmation.rule9.txt)" \
  examples/home-insurance-no-confirmation.mandate.json examples/home-insurance-no-confirmation.trace.json "${KEYS[@]}" "${POLICY[@]}"
out="$("$PY" scripts/validate.py "$M" "$T" --skip-signatures 2>&1)" || true
if ! grep -qxF -- "  note: $(cat testdata/golden/rule9.agents-claim.txt)" <<<"$out" || grep -q "  signed:" <<<"$out"; then
  echo "not ok  --skip-signatures leaves a signed yes as the agent's claim"; echo "$out"; exit 1
fi
echo "ok      --skip-signatures leaves a signed yes as the agent's claim, and lists no signed confirmation"

# Variants of the home example, each re-chained and re-sealed so that only the confirmation can object.
"$PY" - "$M" "$T" "$TMP" <<'EOF'
import copy, json, sys
sys.path.insert(0, "scripts")
import jws
from chain import event_hash, mandate_hash, sha_text
from make_examples import KEY_IDS, sign_mandate, signature

mandate_path, trace_path, out = sys.argv[1:4]
mandate, trace = json.load(open(mandate_path)), json.load(open(trace_path))
CONF = 9


def dump(name, doc):
    json.dump(doc, open(f"{out}/{name}.json", "w"))


def rechain(t):
    prev = t["mandate_ref"]["mandate_hash"]
    for i, ev in enumerate(t["events"]):
        ev["seq"] = i
        ev["prev_hash"] = prev
        ev["hash"] = event_hash(ev)
        prev = ev["hash"]
    t["seal"]["final_event_hash"] = prev


def reseal(t):
    payload = jws.seal_payload(t)
    t["seal"]["signatures"] = [{"signer": role, **signature(holder, jws.SEAL_TYP, payload)}
                               for holder, role in (("home-helper", "agent"), ("newco", "provider"))]
    return t


def sign_at(t, idx, holder="sam", key_id=None, typ=jws.CONFIRMATION_TYP):
    """Sign t's event idx as holder, over the trace as it stands: the events before idx."""
    pl = t["events"][idx]["payload"]
    pl.pop("principal_signature", None)
    previous = ""
    for e in t["events"][:idx]:
        if e["type"] == "human_confirmation" and "principal_signature" in e["payload"]:
            previous = jws.confirmation_ref(jws.confirmation_payload(t["trace_id"], t["mandate_ref"]["mandate_hash"], previous, e["payload"]))
    body = jws.confirmation_payload(t["trace_id"], t["mandate_ref"]["mandate_hash"], previous, pl)
    kid = key_id or KEY_IDS[holder]
    pl["principal_signature"] = {"alg": "EdDSA", "key_id": kid, "value": jws.sign(jws.example_key(holder), "EdDSA", kid, typ, body)}


def variant(name, change, base=trace):
    t = copy.deepcopy(base)
    change(t)
    rechain(t)
    dump(name, reseal(t))


def pl(t, idx=CONF):
    return t["events"][idx]["payload"]


# Forged: signed by a key that is not the one that signed the mandate (R3).
variant("conf-agent-key", lambda t: sign_at(t, CONF, "home-helper"))
variant("conf-provider-key", lambda t: sign_at(t, CONF, "newco"))
variant("conf-other-principal", lambda t: sign_at(t, CONF, "jo"))
# The agent's key under Sam's key id (R4): the id is right, the signature is not.
variant("conf-relabelled-kid", lambda t: sign_at(t, CONF, "home-helper", key_id=KEY_IDS["sam"]))
# Sam signed the right bytes, but as a seal signature (R4).
variant("conf-seal-typ", lambda t: sign_at(t, CONF, typ=jws.SEAL_TYP))


def tampered(change):
    return lambda t: change(pl(t))


# What Sam signed is what the verifier sees: change any of it afterwards (R4).
variant("conf-tampered-summary", tampered(lambda p: p.update(shown_summary_hash=sha_text("Switch to NewCo, for 198 GBP. Approve?"))))
variant("conf-tampered-quote", tampered(lambda p: p.update(quote_id="q_incumbent")))
variant("conf-tampered-amount", tampered(lambda p: p["amount"].update(amount="198.00")))
variant("conf-tampered-decision", tampered(lambda p: p.update(decision="modified")))
variant("conf-tampered-method", tampered(lambda p: p.update(method="voice")))
variant("conf-added-aer", tampered(lambda p: p.update(aer="4.35")))


# A real signed yes moved into another journey, or under another of Sam's mandates (R4).
def other_trace(t):
    real = t["trace_id"]
    t["trace_id"] = "trc_SomewhereElse1"
    sign_at(t, CONF)
    t["trace_id"] = real


def other_mandate(t):
    other = json.load(open("examples/home-insurance-no-confirmation.trace.json"))["mandate_ref"]["mandate_hash"]
    real = t["mandate_ref"]["mandate_hash"]
    t["mandate_ref"]["mandate_hash"] = other
    sign_at(t, CONF)
    t["mandate_ref"]["mandate_hash"] = real


variant("conf-other-trace", other_trace)
variant("conf-other-mandate", other_mandate)


# The same signed yes twice, and a signed yes and decline swapped (R4 on the wrong previous_ref).
def duplicate(t):
    t["events"].insert(CONF + 1, copy.deepcopy(t["events"][CONF]))


def decline_after(t):
    duplicate(t)
    pl(t, CONF + 1)["decision"] = "declined"
    for i, ev in enumerate(t["events"]):
        ev["seq"] = i
    sign_at(t, CONF + 1)


def swapped(t):
    decline_after(t)
    t["events"][CONF], t["events"][CONF + 1] = t["events"][CONF + 1], t["events"][CONF]


variant("conf-duplicate", duplicate)
variant("conf-swapped", swapped)
variant("conf-yes-then-decline", decline_after)


def unsigned_decline(t):
    duplicate(t)
    p = pl(t, CONF + 1)
    p["decision"] = "declined"
    del p["principal_signature"]


variant("conf-unsigned-decline", unsigned_decline)

# A signed event that lacks what a signed confirmation needs, or whose actor is not the principal (R2, R1).
variant("conf-no-summary", tampered(lambda p: p.pop("shown_summary_hash")))
variant("conf-no-quote", tampered(lambda p: p.pop("quote_id")))
variant("conf-no-amount", tampered(lambda p: p.pop("amount")))
variant("conf-all-missing", tampered(lambda p: [p.pop(k) for k in ("shown_summary_hash", "quote_id", "amount")]))
variant("conf-actor", lambda t: t["events"][CONF].update(actor="agent"))


# The yes is genuine; what follows is not what it was a yes to (F2, F3, and the existing quote message).
def committed(amount):
    return lambda t: t["events"][10]["payload"]["amount_committed"].update(amount=amount)


variant("conf-amount-mismatch", committed("198.00"))
variant("conf-quote-mismatch", lambda t: (pl(t).update(quote_id="q_incumbent"), sign_at(t, CONF)))
variant("conf-aer-mismatch", lambda t: (pl(t).update(aer="4.35"), sign_at(t, CONF)))
variant("conf-quote-nowhere", lambda t: (pl(t).update(quote_id="q_nowhere"), sign_at(t, CONF)))
variant("conf-currency-mismatch", lambda t: t["events"][10]["payload"]["amount_committed"].update(currency="EUR"))


# A genuine signed yes must be for the quote the agent selected last: an action on the signed quote after
# another selection gets its own message (golden rule9.signed-other-quote.txt); any other quote, the usual one.
def yes_after_other_selection(t):
    other = copy.deepcopy(t["events"][8])
    other["payload"]["quote_id"] = "q_incumbent"
    t["events"].insert(CONF, other)  # the agent selects q_incumbent after choosing q_newco, before Sam's yes


def yes_for_unselected(t):
    pl(t).update(quote_id="q_incumbent")
    sign_at(t, CONF)
    t["events"][10]["payload"]["quote_id"] = "q_incumbent"  # bought what Sam signed for, though q_newco was selected


def signed_then_unsigned(t):
    """A signed yes covers the first purchase; an unsigned yes (copy without the signature) is all that
    stands behind a second selection and purchase."""
    sel2 = copy.deepcopy(t["events"][8])
    yes2 = copy.deepcopy(t["events"][CONF])
    yes2["payload"].pop("principal_signature")
    act2 = copy.deepcopy(t["events"][10])
    for e in (sel2, yes2, act2):
        e["at"] = t["events"][10]["at"]  # keep event times from going backwards
    t["events"][11:11] = [sel2, yes2, act2]  # after the first action, before the post-sale notice


variant("conf-signed-then-unsigned", signed_then_unsigned)
variant("conf-other-selection", yes_after_other_selection)
variant("conf-unselected", yes_for_unselected)


# R1 and R2 stop R3 and R4 for that event: a wrong key on top changes nothing in the report.
def actor_and_wrong_key(t):
    sign_at(t, CONF, "home-helper")
    t["events"][CONF]["actor"] = "agent"


def missing_and_wrong_key(t):
    sign_at(t, CONF, "home-helper")
    pl(t).pop("shown_summary_hash")


variant("conf-actor-wrongkey", actor_and_wrong_key)
variant("conf-missing-wrongkey", missing_and_wrong_key)

# The policy cannot apply to a mandate that does not ask for a confirmation (N2).
m = copy.deepcopy(mandate)
m["human_confirmation"] = "never"
sign_mandate(m, "sam")
dump("never.mandate", m)


def never(t):
    t["mandate_ref"]["mandate_hash"] = mandate_hash(m)
    sign_at(t, CONF)


variant("never.trace", never)
EOF
SAMKEY="https://wallet.example/.well-known/jwks.json#prn_a91f0c3e"
BADSIG="event 9 (human_confirmation): principal_signature does not verify: the signature does not match the document and key"

# Refused for rule 15 whether or not the policy is on: the yes is not genuine.
for policy in "" "--require-signed-confirmations"; do
  label="${policy:+under the policy, }"
  expect_line "${label}a yes signed with the agent's key is refused (R3), word for word as Go does" \
    "$(cat testdata/golden/rule15.confirm-key.txt)" "$M" "$TMP/conf-agent-key.json" "${KEYS[@]}" $policy
  expect_line "${label}a yes signed with the provider's key is refused (R3)" \
    "event 9 (human_confirmation): principal_signature uses key 'https://newco.example/.well-known/jwks.json#seal-2026', but the mandate was signed with '$SAMKEY'" \
    "$M" "$TMP/conf-provider-key.json" "${KEYS[@]}" $policy
  expect_line "${label}a yes signed with another principal's key is refused (R3)" \
    "event 9 (human_confirmation): principal_signature uses key 'https://wallet.example/.well-known/jwks.json#prn_5d2e7b14', but the mandate was signed with '$SAMKEY'" \
    "$M" "$TMP/conf-other-principal.json" "${KEYS[@]}" $policy
done
expect_line "the agent's key under Sam's key id is refused (R4)" "$BADSIG" "$M" "$TMP/conf-relabelled-kid.json" "${KEYS[@]}"
expect_line "a seal signature over the confirmation bytes is not a confirmation signature (R4)" \
  "event 9 (human_confirmation): principal_signature does not verify: the JWS header has typ 'a-witness-seal', expected 'a-witness-confirmation'" \
  "$M" "$TMP/conf-seal-typ.json" "${KEYS[@]}"
expect_line "a changed summary is refused (R4), word for word as Go does" \
  "$(cat testdata/golden/rule15.confirm-bad-sig.txt)" "$M" "$TMP/conf-tampered-summary.json" "${KEYS[@]}" "${POLICY[@]}"
for what in quote amount decision method; do
  expect_line "a changed $what is refused (R4)" "$BADSIG" "$M" "$TMP/conf-tampered-$what.json" "${KEYS[@]}" "${POLICY[@]}"
done
expect_line "an AER added after signing is refused (R4)" "$BADSIG" "$M" "$TMP/conf-added-aer.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a yes signed for another trace_id is refused (R4)" "$BADSIG" "$M" "$TMP/conf-other-trace.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a yes signed for another of Sam's mandates is refused (R4)" "$BADSIG" "$M" "$TMP/conf-other-mandate.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "the same signed yes twice in one trace is refused at the copy (R4)" \
  "event 10 (human_confirmation): principal_signature does not verify: the signature does not match the document and key" \
  "$M" "$TMP/conf-duplicate.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a swapped yes and signed decline: the decline, now first, is refused (R4)" "$BADSIG" "$M" "$TMP/conf-swapped.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a swapped yes and signed decline: the yes, now second, is refused (R4)" \
  "event 10 (human_confirmation): principal_signature does not verify: the signature does not match the document and key" \
  "$M" "$TMP/conf-swapped.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a signed confirmation without a shown_summary_hash is refused (R2), word for word as Go does" \
  "$(cat testdata/golden/rule15.confirm-needs-summary.txt)" "$M" "$TMP/conf-no-summary.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a signed confirmation without a quote_id is refused (R2)" \
  "event 9 (human_confirmation): a signed confirmation needs quote_id" "$M" "$TMP/conf-no-quote.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a signed confirmation without an amount is refused (R2)" \
  "event 9 (human_confirmation): a signed confirmation needs amount" "$M" "$TMP/conf-no-amount.json" "${KEYS[@]}" "${POLICY[@]}"
for field in shown_summary_hash quote_id amount; do
  expect_line "all three missing fields are named: $field (R2)" \
    "event 9 (human_confirmation): a signed confirmation needs $field" "$M" "$TMP/conf-all-missing.json" "${KEYS[@]}" "${POLICY[@]}"
done
expect_line "a signature on an event whose actor is not the principal is refused (R1), word for word as Go does" \
  "$(cat testdata/golden/rule15.confirm-actor.txt)" "$M" "$TMP/conf-actor.json" "${KEYS[@]}" "${POLICY[@]}"
expect_fail "a refused yes is a broken record, not a mandate breach" \
  "the record is broken or has been tampered with" "$M" "$TMP/conf-agent-key.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a yes signed for a quote nobody offered is caught by rule 8" \
  "event 9 (human_confirmation): refers to quote 'q_nowhere', but no earlier quote_received offered it" \
  "$M" "$TMP/conf-quote-nowhere.json" "${KEYS[@]}" "${POLICY[@]}"

# A genuine yes, followed by a purchase that is not what it was a yes to.
expect_line "a purchase for another amount than the one signed is refused (F2), word for word as Go does" \
  "$(cat testdata/golden/rule9.amount-mismatch.txt)" "$M" "$TMP/conf-amount-mismatch.json" "${KEYS[@]}"
expect_line "a purchase on another quote than the one signed is refused" \
  "event 10 (action_executed): the agent committed 298.00 GBP on quote 'q_newco', but the principal approved quote 'q_incumbent'" \
  "$M" "$TMP/conf-quote-mismatch.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a signed AER the quote did not offer is refused (F3), word for word as Go does" \
  "$(cat testdata/golden/rule9.aer-mismatch.txt)" "$M" "$TMP/conf-aer-mismatch.json" "${KEYS[@]}"
expect_line "a purchase in another currency than the one signed is refused (F2)" \
  "event 10 (action_executed): the agent committed 298.00 EUR, but the principal approved 298.00 GBP" \
  "$M" "$TMP/conf-currency-mismatch.json" "${KEYS[@]}"
expect_line "a signed yes given after the agent selected another quote does not cover the purchase" \
  "$(cat testdata/golden/rule9.signed-other-quote.txt)" \
  "$M" "$TMP/conf-other-selection.json" "${KEYS[@]}"
expect_line "a signed yes for a quote the agent did not select does not cover the purchase" \
  "event 10 (action_executed): the principal signed approval for quote 'q_incumbent', but the agent selected quote 'q_newco'" \
  "$M" "$TMP/conf-unselected.json" "${KEYS[@]}"
expect_line "under the policy an unsigned yes behind a second purchase is refused even after a signed one (F1)" \
  "event 13 (action_executed): the agent committed 298.00 GBP on an approval the principal did not sign, but this verifier counts only approvals the principal signed" \
  "$M" "$TMP/conf-signed-then-unsigned.json" "${KEYS[@]}" "${POLICY[@]}"
# expect_report <label> <the whole report> <validate.py args...>: every line, so an extra one is caught.
expect_report() {
  local label="$1" want="$2"; shift 2
  local out code=0
  out="$("$PY" scripts/validate.py "$@" 2>&1)" || code=$?
  if [[ $code -ne 1 || "$out" != "$want" ]]; then
    echo "not ok  $label (exit $code)"; echo "$out"; echo "-- wanted"; echo "$want"; exit 1
  fi
  echo "ok      $label"
}
BROKEN="the record is broken or has been tampered with"
expect_report "R1 stops R3 and R4: a wrong key and a wrong actor give the actor line alone" \
  "FAIL  conf-actor-wrongkey.json: $BROKEN
  - $(cat testdata/golden/rule15.confirm-actor.txt)" "$M" "$TMP/conf-actor-wrongkey.json" "${KEYS[@]}"
expect_report "R2 stops R3 and R4: a wrong key and a missing summary give the summary line alone" \
  "FAIL  conf-missing-wrongkey.json: $BROKEN
  - $(cat testdata/golden/rule15.confirm-needs-summary.txt)" "$M" "$TMP/conf-missing-wrongkey.json" "${KEYS[@]}"
expect_report "a mismatch with the signed yes reports its verified confirmation reference" \
  "FAIL  conf-amount-mismatch.json: the record is intact, but the agent broke its mandate
  - $(cat testdata/golden/rule9.amount-mismatch.txt)
  signed: $(cat testdata/golden/confirmation.signed.txt)" "$M" "$TMP/conf-amount-mismatch.json" "${KEYS[@]}"
expect_line "an unsigned decline still cancels a signed yes" \
  "event 11 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal, but the mandate requires one every time" \
  "$M" "$TMP/conf-unsigned-decline.json" "${KEYS[@]}" "${POLICY[@]}"
expect_line "a signed decline after a signed yes cancels it" \
  "event 11 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal, but the mandate requires one every time" \
  "$M" "$TMP/conf-yes-then-decline.json" "${KEYS[@]}" "${POLICY[@]}"
expect_pass_line "the policy does not apply to a mandate that never asks, and the report says so (N2), word for word as Go does" \
  "  note: $(cat testdata/golden/rule9.policy-not-applied.txt)" "$TMP/never.mandate.json" "$TMP/never.trace.json" "${KEYS[@]}" "${POLICY[@]}"
expect_no_line "without the policy there is nothing to say about it" \
  "only principal-signed approvals count" "$TMP/never.mandate.json" "$TMP/never.trace.json" "${KEYS[@]}"
# An unsigned yes with a bad signature elsewhere is not looked at when signatures are skipped.
expect_fail "--skip-signatures does not check a confirmation signature" \
  "signatures were not checked (--skip-signatures)" "$M" "$TMP/conf-tampered-summary.json" "${SKIP[@]}"
out="$("$PY" scripts/validate.py "$M" "$TMP/conf-tampered-summary.json" "${SKIP[@]}" 2>&1)" || true
if grep -q "principal_signature" <<<"$out"; then echo "not ok  --skip-signatures checked a confirmation"; echo "$out"; exit 1; fi
echo "ok      --skip-signatures reports no confirmation problem"

expect_usage "--require-signed-confirmations with --skip-signatures is a usage error" "$M" "$T" --skip-signatures --require-signed-confirmations
expect_usage "--require-signed-confirmations without keys is a usage error" "$M" "$T" --require-signed-confirmations
expect_usage "--require-signed-confirmations with only some keys is a usage error" "$M" "$T" --require-signed-confirmations --principal-keys examples/keys.principal.jwks.json

echo "not json" > "$TMP/garbage.json"
expect_fail "unreadable file is reported" "not valid JSON" "$M" "$TMP/garbage.json" "${SKIP[@]}"

"$PY" -c 'import sys; open(sys.argv[1], "w").write("[" * 1001 + "]" * 1001)' "$TMP/too-deep.json"
expect_fail "a document nested 1,001 levels deep is refused, not crashed on" "nested deeper than 1000 levels" "$M" "$TMP/too-deep.json" "${SKIP[@]}"

echo "== documents at the depth limit"
# Exactly 1,000 levels in total: the trace is 1 level, events 2, an event 3, its payload 4, so 996 more.
"$PY" - "$T" "$TMP" <<'EOF'
import json, sys
sys.path.insert(0, "scripts")
import hashlib
from chain import canon, event_hash
src, out = sys.argv[1], sys.argv[2]
DEEP = "[" * 996 + "]" * 996
t = json.load(open(src))
t["events"][2]["payload"]["deep"] = "@@"
prev = t["mandate_ref"]["mandate_hash"]
for i, ev in enumerate(t["events"]):
    ev["prev_hash"] = prev
    if i == 2:
        # rfc8785 cannot canonicalise this depth, so hash with a placeholder and splice in the deep
        # array, which is its own canonical form.
        ev["payload"]["deep"] = "@@"
        text = canon({k: v for k, v in ev.items() if k != "hash"}).decode().replace('"@@"', DEEP)
        ev["hash"] = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    else:
        ev["hash"] = event_hash(ev)
    prev = ev["hash"]
t["seal"]["final_event_hash"] = prev
open(f"{out}/depth-1000.json", "w").write(json.dumps(t).replace('"@@"', DEEP))
open(f"{out}/exactly-1000.json", "w").write("[" * 1000 + "]" * 1000)
EOF
code=0
out="$("$PY" scripts/validate.py "$M" "$TMP/depth-1000.json" "${SKIP[@]}" 2>&1)" || code=$?
if [[ "$out" == *Traceback* || $code -gt 1 ]]; then echo "not ok  a 1,000-level document crashed the validator (exit $code)"; echo "$out"; exit 1; fi
echo "ok      a document exactly 1,000 levels deep does not crash (exit $code: ${out%%$'\n'*})"

"$PY" - "$TMP/exactly-1000.json" <<'EOF'
import sys
sys.path.insert(0, "scripts")
import validate
validate.load(sys.argv[1])  # raises Unreadable if the scan refuses it
assert validate.too_deep("[" * 1001 + "]" * 1001) and not validate.too_deep("[" * 1000 + "]" * 1000)
print("ok      loading accepts exactly 1,000 levels and refuses 1,001")
EOF

# A mandate whose signature header decodes to a 5,000,000-level array: json.loads in jws.verify recurses.
"$PY" - "$M" "$TMP/deep-header-mandate.json" <<'EOF'
import base64, json, sys
m = json.load(open(sys.argv[1]))
header = base64.urlsafe_b64encode(b"[" * 5_000_000).rstrip(b"=").decode()
m["signature"]["value"] = header + ".." + m["signature"]["value"].split("..")[1]
json.dump(m, open(sys.argv[2], "w"))
EOF
out="$("$PY" scripts/validate.py "$TMP/deep-header-mandate.json" "$T" "${KEYS[@]}" 2>&1)" && code=0 || code=$?
if [[ $code -ne 1 || "$out" != FAIL* || "$out" == *Traceback* ]]; then echo "not ok  a deeply nested JWS header (exit $code)"; echo "$out" | tail -5; exit 1; fi
echo "ok      a deeply nested JWS header is a clean FAIL"

echo "all checks passed"
