"""Hashing shared by make_examples.py, make_vectors.py and validate.py.

Canonical JSON is RFC 8785 (JCS), via the rfc8785 library from Trail of
Bits. The Go reference implementation is witness/canon; the two are held
together by the test vectors in testdata/vectors/. See SPEC.md, "Hashing".
"""
import hashlib

import rfc8785


def canon(obj) -> bytes:
    return rfc8785.dumps(obj)


def sha(obj) -> str:
    """Hash of a JSON value's canonical form."""
    return "sha256:" + hashlib.sha256(canon(obj)).hexdigest()


def sha_text(text: str) -> str:
    """Hash of raw text (its UTF-8 bytes, no normalisation), used to reference
    documents and utterances without storing them."""
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def without(obj: dict, key: str) -> dict:
    return {k: v for k, v in obj.items() if k != key}


def mandate_hash(mandate: dict) -> str:
    """A mandate is hashed without its signature, so signing does not change its hash."""
    return sha(without(mandate, "signature"))


def event_hash(event: dict) -> str:
    """An event is hashed without its own hash field."""
    return sha(without(event, "hash"))
