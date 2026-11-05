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

echo "all checks passed"
