"""Generate the worked example mandate and trace with a real hash chain.

Story: Sam's home insurance renewal arrives 25% higher. Sam's agent shops
around, finds a cheaper policy that still meets Sam's must-haves, asks Sam
to confirm, then switches.

Signatures are placeholders in v0.1. Real signing arrives in Phase 2.
Canonicalisation here is sorted-key compact JSON, a stand-in for RFC 8785.
"""
import json
from pathlib import Path

from chain import event_hash, mandate_hash as hash_mandate, sha_text

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "examples"
PLACEHOLDER_SIG = "UNSIGNED-EXAMPLE"


mandate = {
    "spec_version": "0.1",
    "mandate_id": "mdt_7Hq2Lk9Xw3Pz",
    "principal": {
        "principal_ref": "prn_a91f0c3e",
        "type": "consumer",
        "jurisdiction": "GB",
        "support_needs_declared": False,
    },
    "agent": {
        "agent_id": "agt_homehelper_01",
        "operator": "Example Agent Ltd",
        "software": {"name": "home-helper", "version": "0.3.1", "model": "example-model"},
        "public_key_ref": "https://agent.example/.well-known/jwks.json#k1",
    },
    "scope": {
        "product_classes": ["home_insurance"],
        "allowed_actions": ["quote", "compare", "renew", "switch"],
    },
    "limits": {
        "max_price": {"amount": "350.00", "currency": "GBP"},
        "max_price_increase_pct": 10,
        "max_term_months": 12,
        "max_transactions": 1,
        "requirements": [
            {
                "id": "req_excess",
                "text": "Excess no more than 250 GBP",
                "machine_check": {"field": "excess", "op": "lte", "value": "250.00"},
            },
            {
                "id": "req_accidental",
                "text": "Must include accidental damage cover",
                "machine_check": {"field": "cover", "op": "includes", "value": "accidental_damage"},
            },
        ],
    },
    "human_confirmation": "always",
    "consent": {
        "granted_at": "2026-10-01T09:00:00Z",
        "method": "wallet_passkey",
        "terms_hash": sha_text("I allow my agent to renew or switch my home insurance within these limits."),
        "language": "en-GB",
    },
    "validity": {
        "not_before": "2026-10-01T09:00:00Z",
        "expires_at": "2027-01-31T23:59:59Z",
        "revocation_url": "https://wallet.example/mandates/mdt_7Hq2Lk9Xw3Pz/status",
    },
    "signature": {"alg": "ES256", "key_id": "prn_a91f0c3e#wallet", "value": PLACEHOLDER_SIG},
}

mandate_hash = hash_mandate(mandate)

raw_events = [
    ("2026-10-02T08:00:00Z", "intent_captured", "agent", {
        "summary": "Renewal came in at 389 GBP, up from 312 GBP. Check if I can do better, same cover.",
        "utterance_hash": sha_text("my home insurance renewal is way up, sort it"),
    }),
    ("2026-10-02T08:00:05Z", "quote_received", "provider", {
        "quote_id": "q_incumbent", "provider_id": "prov_oldco", "provider_frn": "000001",
        "product_id": "home_std", "price": {"amount": "389.00", "currency": "GBP"},
        "previous_price": {"amount": "312.00", "currency": "GBP"}, "term_months": 12,
        "key_features": {"excess": "250.00", "cover": ["buildings", "contents", "accidental_damage"]},
    }),
    ("2026-10-02T08:01:10Z", "quote_received", "provider", {
        "quote_id": "q_newco", "provider_id": "prov_newco", "provider_frn": "000002",
        "product_id": "home_plus", "price": {"amount": "298.00", "currency": "GBP"},
        "term_months": 12,
        "key_features": {"excess": "200.00", "cover": ["buildings", "contents", "accidental_damage"]},
    }),
    ("2026-10-02T08:01:12Z", "quote_received", "provider", {
        "quote_id": "q_cheapco", "provider_id": "prov_cheapco", "provider_frn": "000003",
        "product_id": "home_basic", "price": {"amount": "241.00", "currency": "GBP"},
        "term_months": 12,
        "key_features": {"excess": "500.00", "cover": ["buildings", "contents"]},
    }),
    ("2026-10-02T08:01:30Z", "requirement_check", "agent", {
        "quote_id": "q_newco",
        "results": [
            {"requirement_id": "req_excess", "passed": True, "detail": "200.00 <= 250.00"},
            {"requirement_id": "req_accidental", "passed": True},
        ],
    }),
    ("2026-10-02T08:01:31Z", "requirement_check", "agent", {
        "quote_id": "q_cheapco",
        "results": [
            {"requirement_id": "req_excess", "passed": False, "detail": "500.00 > 250.00"},
            {"requirement_id": "req_accidental", "passed": False},
        ],
    }),
    ("2026-10-02T08:01:40Z", "alternatives_considered", "agent", {
        "options": [
            {"quote_id": "q_incumbent", "considered": True, "excluded_reason": "Price rise 24.7% exceeds mandate limit of 10%"},
            {"quote_id": "q_newco", "considered": True},
            {"quote_id": "q_cheapco", "considered": True, "excluded_reason": "Fails excess and accidental damage requirements"},
        ],
        "market_coverage_note": "3 providers queried via MCP. Not whole of market.",
    }),
    ("2026-10-02T08:01:45Z", "disclosure_presented", "provider", {
        "document_kind": "ipid",
        "document_hash": sha_text("NewCo Home Plus IPID v4"),
        "document_url": "https://newco.example/docs/home-plus-ipid.pdf",
        "presented_to": "principal",
        "plain_summary": "Covers buildings and contents with accidental damage. 200 GBP excess. Not covered: wear and tear, unoccupied over 60 days.",
    }),
    ("2026-10-02T08:01:50Z", "selection_made", "agent", {
        "quote_id": "q_newco",
        "rationale": "Cheapest option that meets both must-haves. Saves 91 GBP versus renewal and lowers the excess.",
        "within_mandate_limits": True,
    }),
    ("2026-10-02T08:14:02Z", "human_confirmation", "principal", {
        "method": "passkey",
        "decision": "approved",
        "shown_summary_hash": sha_text("Switch to NewCo Home Plus, 298 GBP/yr, excess 200 GBP. Approve?"),
    }),
    ("2026-10-02T08:14:20Z", "action_executed", "provider", {
        "quote_id": "q_newco",
        "provider_reference": "NC-HP-55120",
        "amount_committed": {"amount": "298.00", "currency": "GBP"},
        "payment_mandate_ref": "ap2:pm_example_123",
    }),
    ("2026-10-02T08:14:25Z", "post_sale_notice", "provider", {
        "notice_kind": "cancellation_window",
        "detail": "14 day cooling-off period applies.",
        "deadline": "2026-10-16T23:59:59Z",
    }),
]

events = []
prev = mandate_hash
for seq, (at, etype, actor, payload) in enumerate(raw_events):
    ev = {"seq": seq, "at": at, "type": etype, "actor": actor, "payload": payload, "prev_hash": prev}
    ev["hash"] = event_hash(ev)
    prev = ev["hash"]
    events.append(ev)

trace = {
    "spec_version": "0.1",
    "trace_id": "trc_Rn4Vb8Ty2Mk6",
    "mandate_ref": {"mandate_id": mandate["mandate_id"], "mandate_hash": mandate_hash},
    "journey": {
        "action": "switch",
        "product_class": "home_insurance",
        "started_at": events[0]["at"],
        "ended_at": events[-1]["at"],
        "status": "completed",
        "transport": "mcp",
    },
    "events": events,
    "outcome_evidence": {
        "products_and_services": {"event_seqs": [4, 5], "note": "Selected product met all stated requirements."},
        "price_and_value": {"event_seqs": [1, 6, 8], "note": "Renewal rise caught and a cheaper compliant option chosen."},
        "consumer_understanding": {"event_seqs": [7, 9], "note": "IPID summarised and shown before confirmation."},
        "consumer_support": {"event_seqs": [11], "note": "Cooling-off rights notified."},
    },
    "seal": {
        "final_event_hash": prev,
        "sealed_at": "2026-10-02T08:14:30Z",
        "signatures": [
            {"signer": "agent", "alg": "ES256", "key_id": "agt_homehelper_01#k1", "value": PLACEHOLDER_SIG},
            {"signer": "provider", "alg": "ES256", "key_id": "prov_newco#k1", "value": PLACEHOLDER_SIG},
        ],
    },
}

OUT.mkdir(exist_ok=True)
(OUT / "home-insurance-switch.mandate.json").write_text(json.dumps(mandate, indent=2) + "\n")
(OUT / "home-insurance-switch.trace.json").write_text(json.dumps(trace, indent=2) + "\n")
print("wrote examples; mandate_hash", mandate_hash)
