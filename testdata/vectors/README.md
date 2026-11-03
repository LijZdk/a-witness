# Test vectors

Known inputs with known outputs, so that any implementation of a-witness, in any language, can check itself. They are language-neutral JSON. Each file has a `description`, a `generated_by` line, and a `vectors` array.

| File | What it tests | Expected outputs come from |
|---|---|---|
| [`canon.json`](canon.json) | RFC 8785 canonical JSON: key order, string escaping, number forms, and inputs that **must be rejected** (duplicate keys, unpaired surrogates, invalid UTF-8, numbers out of range, trailing data) | The `rfc8785` Python library |
| [`numbers.json`](numbers.json) | How RFC 8785 writes 1,594 IEEE 754 doubles: the RFC's own examples, the boundaries where notation switches, and seeded random values | JavaScript's `JSON.stringify`, which RFC 8785 defines number formatting by |
| [`hashes.json`](hashes.json) | a-witness hashes of text, mandates (without `signature`) and events (without `hash`) | `scripts/chain.py` |

The worked examples in [`examples/`](../../examples/) are also vectors: every hash in them must verify.

## Using them

- **canon.json.** For a case with `output`, canonicalise `input` and compare bytes. For a case with `"error": true`, your implementation must refuse the input. Where the bytes themselves are the problem, the input is given as hex in `input_hex`.
- **numbers.json.** Read `bits` as the 64-bit pattern of a double, serialise it, and compare with `output`.
- **hashes.json.** Hash `input` according to `kind` and compare with `hash`.

## Agreement so far

| Implementation | canon | numbers | hashes | examples |
|---|---|---|---|---|
| Go, [`witness/canon`](../../witness/canon) and [`witness`](../../witness) | ✓ | ✓ | ✓ | ✓ |
| Python, [`scripts/chain.py`](../../scripts/chain.py) (`rfc8785` library) | generator | ✓ | generator | ✓ |

CI checks every cell marked ✓ on each push.

## Regenerating

```bash
python scripts/make_vectors.py          # canon.json, hashes.json
node scripts/make_number_vectors.mjs    # numbers.json
```

Both are deterministic. CI regenerates them and fails if the committed files differ, so never edit these files by hand.

Signature vectors arrive with signing, later in Phase 2.
