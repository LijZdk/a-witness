"""Hashing shared by make_examples.py and validate.py.

v0.1 canonicalisation is sorted-key compact JSON, a stand-in for RFC 8785
(JCS). The two agree for the documents in this repo because money is carried
as strings and the only numbers are small integers. Phase 2 replaces this
with real RFC 8785.
"""
import hashlib
import json


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(obj) -> str:
    """Hash of a JSON value's canonical form."""
    return "sha256:" + hashlib.sha256(canon(obj)).hexdigest()


def sha_text(text: str) -> str:
    """Hash of raw text, used to reference documents and utterances without storing them."""
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def without(obj: dict, key: str) -> dict:
    return {k: v for k, v in obj.items() if k != key}


def mandate_hash(mandate: dict) -> str:
    """A mandate is hashed without its signature, so signing does not change its hash."""
    return sha(without(mandate, "signature"))


def event_hash(event: dict) -> str:
    """An event is hashed without its own hash field."""
    return sha(without(event, "hash"))
