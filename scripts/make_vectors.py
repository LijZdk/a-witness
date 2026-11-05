"""Generate testdata/vectors/canon.json and testdata/vectors/hashes.json.

Expected outputs come from the Python implementation (chain.py, which uses
the rfc8785 library), never from the Go code they test. Number formatting
vectors come from JavaScript instead; see make_number_vectors.mjs.

Run with: python scripts/make_vectors.py
"""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

import jws
from chain import canon, event_hash, mandate_hash, sha_text

OUT = Path(__file__).resolve().parent.parent / "testdata" / "vectors"


def parse(text):
    # RFC 8785 reads every number as an IEEE 754 double, integers included.
    return json.loads(text, parse_int=float)


VALID = [
    ("rfc8785 section 3.2.2 example",
     '{\n  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],\n'
     '  "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",\n'
     '  "literals": [null, true, false]\n}'),
    ("rfc8785 section 3.2.3 key sorting: UTF-16 order puts the emoji before U+FB33",
     '{\n  "\\u20ac": "Euro Sign",\n  "\\r": "Carriage Return",\n'
     '  "\\ufb33": "Hebrew Letter Dalet With Dagesh",\n  "1": "One",\n'
     '  "\\ud83d\\ude00": "Emoji: Grinning Face",\n  "\\u0080": "Control",\n'
     '  "\\u00f6": "Latin Small Letter O With Diaeresis"\n}'),
    ("whitespace is removed and nested keys sorted", ' { "b" : [ 1 , { "d" : 1 , "c" : 2 } ] , "a" : { } } '),
    ("empty object", "{}"),
    ("empty array", "[]"),
    ("top-level string", '"x"'),
    ("top-level number", "3"),
    ("top-level literal", "true"),
    ("control characters: short escapes where they exist, lowercase \\u00xx otherwise",
     '"\\u0000\\u0008\\u0009\\u000a\\u000c\\u000d\\u001f"'),
    ("DEL, U+2028 and non-ASCII are written literally, solidus unescaped", '"\\u007f \\u2028 caf\\u00e9 \\/"'),
    ("literal UTF-8 input stays literal", '"café €"'),
    ("number forms: exponent, trailing zeros, negative zero", "[1E2, 1.0, 0.10, -0, -0.0, 1e21, 1e-7, 1e-6]"),
    ("integers beyond 2^53 are read as doubles", "[9007199254740993, 123456789012345678901234567890]"),
    ("underflow reads as zero, as in JavaScript", "1e-400"),
    # json.loads cannot read 1,000 levels (its recursion limit is about that), and
    # the canonical form of nested empty arrays is the input itself, so the
    # expected output is that text directly (see main).
    ("nesting at exactly 1,000 levels is accepted", "[" * 1000 + "]" * 1000),
    ("an a-witness event",
     '{"seq": 0, "at": "2026-10-02T08:00:00Z", "type": "intent_captured", "actor": "agent",'
     ' "payload": {"summary": "Renewal came in at 389 GBP.", "utterance_hash":'
     ' "sha256:c98347474205378879e9e1f37612aa68dc81ec382652d712c128a57aaf61daff"},'
     ' "prev_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}'),
]

# Inputs a conforming implementation must reject. "input" is the JSON text;
# "input_hex" is used instead where the bytes themselves are the problem.
INVALID = [
    ("duplicate object key", {"input": '{"a": 1, "a": 2}'}),
    ("duplicate key after unescaping", {"input": '{"a": 1, "\\u0061": 2}'}),
    ("unpaired high surrogate", {"input": '"\\ud800"'}),
    ("unpaired low surrogate", {"input": '"\\udc00"'}),
    ("high surrogate followed by a non-surrogate", {"input": '"\\ud800\\u0041"'}),
    ("surrogate pair in the wrong order", {"input": '"\\ude00\\ud83d"'}),
    ("invalid UTF-8", {"input_hex": "22ff22"}),
    ("overlong UTF-8 encoding", {"input_hex": "22c0af22"}),
    ("number too large for a double", {"input": "1e400"}),
    ("NaN", {"input": "NaN"}),
    ("Infinity", {"input": "Infinity"}),
    ("two top-level values", {"input": "{} {}"}),
    ("trailing comma", {"input": "[1,]"}),
    ("leading zero", {"input": "01"}),
    ("single-quoted string", {"input": "'x'"}),
    ("empty input", {"input": ""}),
    ("nesting deeper than 1,000 levels", {"input": "[" * 1001 + "]" * 1001}),
]

MANDATE = {
    "spec_version": "0.1",
    "mandate_id": "mdt_vectorMandate01",
    "human_confirmation": "always",
    "limits": {"max_price_increase_pct": 7.5},
    "signature": {"alg": "ES256", "key_id": "k1", "value": "ignored when hashing"},
}

EVENT = {
    "seq": 3,
    "at": "2026-10-02T08:01:12Z",
    "type": "quote_received",
    "actor": "provider",
    "payload": {
        "quote_id": "q_vector",
        "price": {"amount": "241.00", "currency": "GBP"},
        "key_features": {"ratio": 0.1, "big": 1e21, "\U0001f600": "emoji key", "דּ": "sorts after the emoji"},
    },
    "prev_hash": "sha256:" + "ab" * 32,
    "hash": "sha256:" + "00" * 32,
}

HASHES = [
    {"name": "text: consent wording", "kind": "text",
     "input": "I allow my agent to renew or switch my home insurance within these limits."},
    {"name": "text: empty", "kind": "text", "input": ""},
    {"name": "text: non-ASCII is hashed as UTF-8 with no normalisation", "kind": "text", "input": "café"},
    {"name": "text: decomposed form hashes differently", "kind": "text", "input": "café"},
    {"name": "mandate: the signature field is left out", "kind": "mandate", "input": MANDATE},
    {"name": "event: the hash field is left out; floats and non-BMP keys follow RFC 8785", "kind": "event", "input": EVENT},
]


def hash_of(case):
    kind, value = case["kind"], case["input"]
    if kind == "text":
        return sha_text(value)
    if kind == "mandate":
        return mandate_hash(value)
    return event_hash(value)


def signature_vectors():
    """Detached JWS cases (SPEC.md, "Signatures"). alg, kid and typ are what the verifier
    expects; jwk is the key it verifies with. EdDSA cases also give the private key seed,
    because Ed25519 is deterministic: an implementation must reproduce jws exactly."""
    def seed(name):
        return hashlib.sha256(b"a-witness example key: " + name.encode()).digest()

    ed, other = jws.example_key("vector ed25519"), jws.example_key("vector other")
    p256_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    es = ec.derive_private_key(int.from_bytes(seed("vector p256"), "big") % (p256_order - 1) + 1, ec.SECP256R1())
    ed_kid, es_kid = "https://keys.example/jwks.json#ed", "https://keys.example/jwks.json#p256"
    ed_jwk, es_jwk = jws.public_jwk(ed.public_key(), ed_kid), jws.public_jwk(es.public_key(), es_kid)
    mandate = canon({"mandate_id": "mdt_vectorMandate01", "spec_version": "0.1"})
    trace = canon({"trace_id": "trc_vectorTrace0001", "journey": {"status": "completed"}, "note": "café 😀"})

    def case(name, valid, jws_value, alg="EdDSA", kid=ed_kid, typ=jws.MANDATE_TYP, jwk=ed_jwk, payload=mandate, **extra):
        return {"name": name, "valid": valid, "alg": alg, "kid": kid, "typ": typ, "jwk": jwk,
                "payload": payload.decode(), "jws": jws_value, **extra}

    good = jws.sign(ed, "EdDSA", ed_kid, jws.MANDATE_TYP, mandate)
    protected, sig = good.split("..")
    es_protected, es_data = jws.signing_input({"alg": "ES256", "kid": es_kid, "typ": jws.MANDATE_TYP}, mandate)
    return [
        case("EdDSA mandate signature", True, good, seed=seed("vector ed25519").hex()),
        case("EdDSA seal signature over non-ASCII content", True,
             jws.sign(ed, "EdDSA", ed_kid, jws.SEAL_TYP, trace), typ=jws.SEAL_TYP, payload=trace, seed=seed("vector ed25519").hex()),
        case("ES256 mandate signature", True, jws.sign(es, "ES256", es_kid, jws.MANDATE_TYP, mandate),
             alg="ES256", kid=es_kid, jwk=es_jwk),
        case("payload changed after signing", False, good, payload=canon({"mandate_id": "mdt_vectorMandate02", "spec_version": "0.1"})),
        case("mandate signature presented as a seal signature", False, good, typ=jws.SEAL_TYP),
        case("header names a different key", False, jws.sign(ed, "EdDSA", "https://keys.example/jwks.json#other", jws.MANDATE_TYP, mandate)),
        case("header claims a different algorithm", False,
             jws.sign(ed, "EdDSA", ed_kid, jws.MANDATE_TYP, mandate, header={"alg": "ES256", "kid": ed_kid, "typ": jws.MANDATE_TYP})),
        case("header has an extra member", False,
             jws.sign(ed, "EdDSA", ed_kid, jws.MANDATE_TYP, mandate, header={"alg": "EdDSA", "crit": ["b64"], "kid": ed_kid, "typ": jws.MANDATE_TYP})),
        case("signed by a different key", False, jws.sign(other, "EdDSA", ed_kid, jws.MANDATE_TYP, mandate)),
        case("ES256 signature in ASN.1 DER instead of R and S", False,
             f"{es_protected}..{jws.b64(es.sign(es_data, ec.ECDSA(ec.hashes.SHA256(), deterministic_signing=True)))}",
             alg="ES256", kid=es_kid, jwk=es_jwk),
        case("EdDSA expected but the key is P-256", False, good, jwk=es_jwk),
        case("payload attached instead of detached", False, f"{protected}.{jws.b64(mandate)}.{sig}"),
        case("base64url padding", False, f"{protected}..{sig}=="),
    ]


def write(name, header, items):
    lines = ",\n".join("    " + json.dumps(i, ensure_ascii=False) for i in items)
    head = json.dumps(header, indent=2, ensure_ascii=False)[:-2]
    (OUT / name).write_text(f'{head},\n  "vectors": [\n{lines}\n  ]\n}}\n')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    canon_cases = [{"name": n, "input": t, "output": t if t.startswith("[[[") else canon(parse(t)).decode()}
                   for n, t in VALID]
    canon_cases += [{"name": n, **c, "error": True} for n, c in INVALID]
    write("canon.json", {
        "description": "RFC 8785 canonicalisation. A case with \"output\" must produce exactly that text; "
                       "a case with \"error\": true must be rejected. \"input_hex\" gives raw bytes where "
                       "the bytes themselves are the problem.",
        "generated_by": "scripts/make_vectors.py, using the rfc8785 Python library",
    }, canon_cases)
    write("hashes.json", {
        "description": "a-witness hashes (SPEC.md, \"Hashing\"). kind \"text\": SHA-256 of the UTF-8 bytes. "
                       "kind \"mandate\": of the canonical JSON without \"signature\". kind \"event\": of the "
                       "canonical JSON without \"hash\".",
        "generated_by": "scripts/make_vectors.py, using scripts/chain.py",
    }, [{**c, "hash": hash_of(c)} for c in HASHES])
    signatures = signature_vectors()
    write("signatures.json", {
        "description": "Detached JWS signatures (SPEC.md, \"Signatures\"). Verify jws over payload (as UTF-8) "
                       "with jwk, expecting header values alg, kid and typ; valid says whether that must succeed. "
                       "Where seed is given (Ed25519 private key, hex), signing payload must reproduce jws exactly.",
        "generated_by": "scripts/make_vectors.py, using scripts/jws.py and the cryptography library",
    }, signatures)
    print(f"wrote {len(canon_cases)} canon, {len(HASHES)} hash and {len(signatures)} signature vectors")


if __name__ == "__main__":
    main()
