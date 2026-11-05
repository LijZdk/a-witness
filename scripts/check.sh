#!/usr/bin/env bash
# Everything CI runs. Usage: scripts/check.sh  (set PYTHON to override the interpreter)
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
M=examples/home-insurance-switch.mandate.json
T=examples/home-insurance-switch.trace.json
KEYS=(--keys examples/keys.jwks.json)  # the examples' public keys
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
expect_fail "edited price is detected" "event 2: hash does not match" "$M" "$TMP/tampered.json"

"$PY" -c 'import json,sys; t=json.load(open(sys.argv[1])); del t["mandate_ref"]; json.dump(t, open(sys.argv[2], "w"))' "$T" "$TMP/no-ref.json"
expect_fail "schema-invalid trace is reported, not crashed on" "mandate_ref" "$M" "$TMP/no-ref.json"

"$PY" -c 'import json,sys; t=json.load(open(sys.argv[1])); del t["events"][2]["payload"]["aer"]; json.dump(t, open(sys.argv[2], "w"))' \
  examples/fixed-rate-savings-switch.trace.json "$TMP/no-rate.json"
expect_fail "quote with neither price nor rate is rejected" "needs at least one of: price, aer" \
  examples/fixed-rate-savings-switch.mandate.json "$TMP/no-rate.json"

# Variants whose hash chain is recomputed after the edit, as a forger would,
# so the chain itself is valid. The reference variants are checked without
# keys, so that only the reference check can object; the rewrites are checked
# with keys, to show the signatures catch what the chain cannot.
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
  "event 8 (selection_made): refers to quote 'q_nowhere', but no earlier quote_received offered it" "$M" "$TMP/dangling-ref.json"
expect_fail "two quotes sharing an id is caught" \
  "event 3 (quote_received): quote_id 'q_newco' was already used by event 2" "$M" "$TMP/duplicate-quote.json"

expect_fail "a yes withdrawn before the purchase is flagged as a mandate breach" \
  "the record is intact, but the agent broke its mandate" "$M" "$TMP/declined-after-approval.json"
expect_fail "a declined yes leaves the purchase without an approval" \
  "event 11 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal" "$M" "$TMP/declined-after-approval.json"
expect_fail "a yes given before the choice was made does not cover the purchase" \
  "event 10 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal" "$M" "$TMP/approval-before-selection.json"
expect_fail "a yes with no choice made at all is not an approval of the purchase" \
  "event 9 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal" "$M" "$TMP/approval-without-selection.json"
expect_fail "a yes given before the choice is still a mandate breach, not a broken record" \
  "the record is intact, but the agent broke its mandate" "$M" "$TMP/approval-before-selection.json"
expect_fail "a yes recorded by the agent is not the principal's yes" \
  "event 10 (action_executed): the agent committed 298.00 GBP without an approved human_confirmation from the principal" "$M" "$TMP/agent-approval.json"
expect_fail "a yes recorded by the agent is a mandate breach, not a broken record" \
  "the record is intact, but the agent broke its mandate" "$M" "$TMP/agent-approval.json"
expect_fail "a purchase on a different quote than the one approved is flagged as a mandate breach" \
  "the record is intact, but the agent broke its mandate" "$M" "$TMP/different-quote.json"
expect_fail "the quote approved is named in the finding" \
  "on quote 'q_cheapco', but the principal approved quote 'q_newco'" "$M" "$TMP/different-quote.json"

expect_fail "a re-hashed rewrite is caught by the seal signatures" \
  "seal signature 0 (agent) does not verify" "$M" "$TMP/rewritten-price.json" "${KEYS[@]}"
expect_fail "a changed journey status is caught, because the seal covers the whole trace" \
  "seal signature 1 (provider) does not verify" "$M" "$TMP/status-changed.json" "${KEYS[@]}"
"$PY" -c 'import json,sys; m=json.load(open(sys.argv[1])); m["limits"]["max_transactions"]=5; json.dump(m, open(sys.argv[2], "w"))' "$M" "$TMP/mandate-edited.json"
expect_fail "an edited mandate is caught by the principal's signature" \
  "mandate signature does not verify" "$TMP/mandate-edited.json" "$T" "${KEYS[@]}"
echo '{"keys": []}' > "$TMP/no-keys.jwks.json"
expect_fail "a key missing from the key file is reported" \
  "is not in the key file" "$M" "$T" --keys "$TMP/no-keys.jwks.json"

echo "not json" > "$TMP/garbage.json"
expect_fail "unreadable file is reported" "not valid JSON" "$M" "$TMP/garbage.json"

"$PY" -c 'import sys; open(sys.argv[1], "w").write("[" * 1001 + "]" * 1001)' "$TMP/too-deep.json"
expect_fail "a document nested 1,001 levels deep is refused, not crashed on" "nested deeper than 1000 levels" "$M" "$TMP/too-deep.json"

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
out="$("$PY" scripts/validate.py "$M" "$TMP/depth-1000.json" 2>&1)" || code=$?
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
