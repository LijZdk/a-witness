"""Signatures for a-witness: detached JWS with ES256 or EdDSA (SPEC.md, "Signatures").

The Python counterpart of the Go package witness/sign. Used to sign the
examples, generate the signature test vectors, and check signatures in
validate.py.
"""
import base64
import hashlib
import json
import re

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from chain import canon, without

MANDATE_TYP = "a-witness-mandate"
SEAL_TYP = "a-witness-seal"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    """Strict base64url without padding, as RFC 7515 requires."""
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("not valid base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64(data) != text:  # rejects non-zero trailing bits
        raise ValueError("not valid base64url")
    return data


def mandate_payload(mandate: dict) -> bytes:
    """A mandate is signed without its signature: the same bytes its hash covers."""
    return canon(without(mandate, "signature"))


def seal_payload(trace: dict) -> bytes:
    """A seal signature covers the whole trace except the seal's signatures."""
    return canon({**trace, "seal": without(trace["seal"], "signatures")})


def example_key(name: str) -> ed25519.Ed25519PrivateKey:
    """A throwaway Ed25519 key derived from a public string. For examples and tests only:
    anyone can derive it, so it proves nothing about who signed."""
    return ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"a-witness example key: " + name.encode()).digest())


def signing_input(header: dict, payload: bytes) -> tuple[str, bytes]:
    protected = b64(rfc8785.dumps(header))
    return protected, f"{protected}.{b64(payload)}".encode()


def sign(key, alg: str, kid: str, typ: str, payload: bytes, header: dict | None = None) -> str:
    """Detached JWS: header..signature. `header` overrides the normal one, for test vectors only."""
    protected, data = signing_input(header or {"alg": alg, "kid": kid, "typ": typ}, payload)
    if alg == "EdDSA":
        sig = key.sign(data)
    elif alg == "ES256":
        # Deterministic (RFC 6979), so regenerated vectors stay identical. Verifiers cannot tell the difference.
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raise ValueError(f"unsupported algorithm {alg!r}")
    return f"{protected}..{b64(sig)}"


def _no_duplicates(pairs):
    seen = set()
    for name, _ in pairs:
        if name in seen:
            raise ValueError(f"the JWS header has a duplicate member {name!r}")
        seen.add(name)
    return dict(pairs)


def parse_header(raw: bytes) -> dict:
    """The protected header as a dict. Like witness/sign, refuse duplicate member names
    (json.loads alone would keep the last) and anything that is not JSON."""
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except UnicodeDecodeError:
        raise ValueError("the JWS header is not valid UTF-8") from None
    except json.JSONDecodeError as e:
        raise ValueError(f"the JWS header is not valid JSON: {e}") from None
    except ValueError:
        raise
    except RecursionError:
        raise ValueError("the JWS header is too deeply nested") from None
    except Exception as e:
        raise ValueError(f"the JWS header cannot be parsed: {type(e).__name__}") from None


def sign_raw_header(key, header_bytes: bytes, payload: bytes) -> str:
    """Ed25519 detached JWS over exactly these header bytes, for test vectors only: a dict
    cannot hold the malformed headers (such as duplicate members) that vectors need."""
    protected = b64(header_bytes)
    return f"{protected}..{b64(key.sign(f'{protected}.{b64(payload)}'.encode()))}"


def verify(jws: str, payload: bytes, public_key, alg: str, kid: str, typ: str) -> None:
    """Raise ValueError saying why, unless jws is a valid signature over payload."""
    parts = jws.split(".")
    if len(parts) != 3 or parts[1] != "":
        raise ValueError("not a detached JWS (expected header..signature)")
    header = parse_header(unb64(parts[0]))
    if not isinstance(header, dict) or set(header) != {"alg", "kid", "typ"}:
        raise ValueError("the JWS header must hold exactly alg, kid and typ")
    for name, want in (("alg", alg), ("kid", kid), ("typ", typ)):
        if header[name] != want:
            raise ValueError(f"the JWS header has {name} {header[name]!r}, expected {want!r}")
    sig = unb64(parts[2])
    data = f"{parts[0]}.{b64(payload)}".encode()
    try:
        if alg == "EdDSA" and isinstance(public_key, ed25519.Ed25519PublicKey):
            if len(sig) != 64:
                raise InvalidSignature
            public_key.verify(sig, data)
        elif alg == "ES256" and isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.curve.name == "secp256r1":
            if len(sig) != 64:
                raise InvalidSignature
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            public_key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"the key does not fit {alg}")
    except InvalidSignature:
        raise ValueError("the signature does not match the document and key") from None


def public_jwk(public_key, kid: str) -> dict:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))}
    numbers = public_key.public_numbers()
    return {"kty": "EC", "crv": "P-256", "kid": kid,
            "x": b64(numbers.x.to_bytes(32, "big")), "y": b64(numbers.y.to_bytes(32, "big"))}


def load_jwk(jwk: dict):
    if "d" in jwk:
        raise ValueError(f"key {jwk.get('kid')!r} includes private key material")
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(unb64(jwk["x"]))
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x, y = (int.from_bytes(unb64(jwk[c]), "big") for c in ("x", "y"))
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    raise ValueError(f"unsupported key type {jwk.get('kty')}/{jwk.get('crv')}")


def load_jwks(path) -> dict:
    """Public keys from a JWKS file, by kid."""
    keys = {}
    for jwk in json.loads(open(path).read())["keys"]:
        if jwk["kid"] in keys:
            raise ValueError(f"two keys with kid {jwk['kid']!r}")
        keys[jwk["kid"]] = load_jwk(jwk)
    return keys
