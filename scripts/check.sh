#!/usr/bin/env bash
# Everything CI runs. Usage: scripts/check.sh  (set PYTHON to override the interpreter)
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
M=examples/home-insurance-switch.mandate.json
T=examples/home-insurance-switch.trace.json
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
"$PY" scripts/validate.py "$M" "$T"
"$PY" scripts/validate.py examples/fixed-rate-savings-switch.mandate.json examples/fixed-rate-savings-switch.trace.json

echo "== the no-confirmation example fails, as a mandate breach rather than a broken record"
expect_fail "purchase without the principal's yes is flagged" \
  "the record is intact, but the agent broke its mandate" \
  examples/home-insurance-no-confirmation.mandate.json examples/home-insurance-no-confirmation.trace.json

echo "== broken inputs fail cleanly"
sed 's/"298.00"/"198.00"/' "$T" > "$TMP/tampered.json"
expect_fail "edited price is detected" "event 2: hash does not match" "$M" "$TMP/tampered.json"

"$PY" -c 'import json,sys; t=json.load(open(sys.argv[1])); del t["mandate_ref"]; json.dump(t, open(sys.argv[2], "w"))' "$T" "$TMP/no-ref.json"
expect_fail "schema-invalid trace is reported, not crashed on" "mandate_ref" "$M" "$TMP/no-ref.json"

"$PY" -c 'import json,sys; t=json.load(open(sys.argv[1])); del t["events"][2]["payload"]["aer"]; json.dump(t, open(sys.argv[2], "w"))' \
  examples/fixed-rate-savings-switch.trace.json "$TMP/no-rate.json"
expect_fail "quote with neither price nor rate is rejected" "needs at least one of: price, aer" \
  examples/fixed-rate-savings-switch.mandate.json "$TMP/no-rate.json"

# Variants whose hash chain is recomputed after the edit, so the chain is valid
# and only the quote reference check can object.
"$PY" - "$T" "$TMP" <<'EOF'
import json, sys
sys.path.insert(0, "scripts")
from chain import event_hash

src, out = sys.argv[1], sys.argv[2]

def variant(name, mutate):
    t = json.load(open(src))
    mutate(t["events"])
    prev = t["mandate_ref"]["mandate_hash"]
    for ev in t["events"]:
        ev["prev_hash"] = prev
        ev["hash"] = event_hash(ev)
        prev = ev["hash"]
    t["seal"]["final_event_hash"] = prev
    json.dump(t, open(f"{out}/{name}.json", "w"))

variant("dangling-ref", lambda e: e[8]["payload"].update(quote_id="q_nowhere"))
variant("duplicate-quote", lambda e: e[3]["payload"].update(quote_id="q_newco"))
EOF
expect_fail "selection of a quote nobody offered is caught" \
  "event 8 (selection_made): refers to quote 'q_nowhere', but no earlier quote_received offered it" "$M" "$TMP/dangling-ref.json"
expect_fail "two quotes sharing an id is caught" \
  "event 3 (quote_received): quote_id 'q_newco' was already used by event 2" "$M" "$TMP/duplicate-quote.json"

echo "not json" > "$TMP/garbage.json"
expect_fail "unreadable file is reported" "not valid JSON" "$M" "$TMP/garbage.json"

echo "all checks passed"
