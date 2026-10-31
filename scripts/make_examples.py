"""Generate the example mandates and traces with real hash chains.

Every example is an untampered record: its hashes are genuine. What differs
is whether the journey it records obeyed the mandate.

  home-insurance-switch            PASSES. Sam's renewal arrives 25% higher.
                                   The agent shops around, finds a cheaper
                                   policy that meets Sam's must-haves, asks
                                   Sam to confirm, then switches.

  home-insurance-no-confirmation   FAILS. Same shopping, but Sam never answers
                                   the request to approve. With the quote about
                                   to expire, the agent buys anyway, although
                                   the mandate says it must always ask first.

Never hand-edit the files in examples/. Change this script and run it again.

Signatures are placeholders in v0.1. Real signing arrives in Phase 2.
Canonicalisation here is sorted-key compact JSON, a stand-in for RFC 8785.
"""
import json
from pathlib import Path

from chain import event_hash, mandate_hash as hash_mandate, sha_text

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "examples"
PLACEHOLDER_SIG = "UNSIGNED-EXAMPLE"


def home_mandate(mandate_id):
    """Sam's permission slip: switch home insurance within limits, and always ask before buying."""
    return {
        "spec_version": "0.1",
        "mandate_id": mandate_id,
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
            "revocation_url": f"https://wallet.example/mandates/{mandate_id}/status",
        },
        "signature": {"alg": "ES256", "key_id": "prn_a91f0c3e#wallet", "value": PLACEHOLDER_SIG},
    }


def shopping_events(newco_valid_until=None):
    """Events 0-8, common to both stories: capture the ask, get quotes, check them, pick NewCo."""
    newco_quote = {
        "quote_id": "q_newco", "provider_id": "prov_newco", "provider_frn": "000002",
        "product_id": "home_plus", "price": {"amount": "298.00", "currency": "GBP"},
        "term_months": 12,
        "key_features": {"excess": "200.00", "cover": ["buildings", "contents", "accidental_damage"]},
    }
    if newco_valid_until:
        newco_quote["valid_until"] = newco_valid_until

    return [
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
        ("2026-10-02T08:01:10Z", "quote_received", "provider", newco_quote),
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
    ]


def purchase_events(at):
    """NewCo binds the policy and sends the cooling-off notice."""
    executed, notice = at
    return [
        (executed, "action_executed", "provider", {
            "quote_id": "q_newco",
            "provider_reference": "NC-HP-55120",
            "amount_committed": {"amount": "298.00", "currency": "GBP"},
            "payment_mandate_ref": "ap2:pm_example_123",
        }),
        (notice, "post_sale_notice", "provider", {
            "notice_kind": "cancellation_window",
            "detail": "14 day cooling-off period applies.",
            "deadline": "2026-10-16T23:59:59Z",
        }),
    ]


def chain_events(mandate_hash, raw_events):
    events, prev = [], mandate_hash
    for seq, (at, etype, actor, payload) in enumerate(raw_events):
        ev = {"seq": seq, "at": at, "type": etype, "actor": actor, "payload": payload, "prev_hash": prev}
        ev["hash"] = event_hash(ev)
        prev = ev["hash"]
        events.append(ev)
    return events


def build_trace(trace_id, mandate, raw_events, sealed_at, outcome_evidence=None):
    m_hash = hash_mandate(mandate)
    events = chain_events(m_hash, raw_events)
    trace = {
        "spec_version": "0.1",
        "trace_id": trace_id,
        "mandate_ref": {"mandate_id": mandate["mandate_id"], "mandate_hash": m_hash},
        "journey": {
            "action": "switch",
            "product_class": "home_insurance",
            "started_at": events[0]["at"],
            "ended_at": events[-1]["at"],
            "status": "completed",
            "transport": "mcp",
        },
        "events": events,
    }
    if outcome_evidence:
        trace["outcome_evidence"] = outcome_evidence
    trace["seal"] = {
        "final_event_hash": events[-1]["hash"],
        "sealed_at": sealed_at,
        "signatures": [
            {"signer": "agent", "alg": "ES256", "key_id": "agt_homehelper_01#k1", "value": PLACEHOLDER_SIG},
            {"signer": "provider", "alg": "ES256", "key_id": "prov_newco#k1", "value": PLACEHOLDER_SIG},
        ],
    }
    return trace


def write(name, mandate, trace):
    OUT.mkdir(exist_ok=True)
    (OUT / f"{name}.mandate.json").write_text(json.dumps(mandate, indent=2) + "\n")
    (OUT / f"{name}.trace.json").write_text(json.dumps(trace, indent=2) + "\n")
    print(f"wrote {name}; mandate_hash {trace['mandate_ref']['mandate_hash']}")


def switch_example():
    """The good journey: Sam approves before the agent buys."""
    mandate = home_mandate("mdt_7Hq2Lk9Xw3Pz")
    raw = shopping_events() + [
        ("2026-10-02T08:14:02Z", "human_confirmation", "principal", {
            "method": "passkey",
            "decision": "approved",
            "shown_summary_hash": sha_text("Switch to NewCo Home Plus, 298 GBP/yr, excess 200 GBP. Approve?"),
        }),
    ] + purchase_events(("2026-10-02T08:14:20Z", "2026-10-02T08:14:25Z"))
    trace = build_trace("trc_Rn4Vb8Ty2Mk6", mandate, raw, "2026-10-02T08:14:30Z", outcome_evidence={
        "products_and_services": {"event_seqs": [4, 5], "note": "Selected product met all stated requirements."},
        "price_and_value": {"event_seqs": [1, 6, 8], "note": "Renewal rise caught and a cheaper compliant option chosen."},
        "consumer_understanding": {"event_seqs": [7, 9], "note": "IPID summarised and shown before confirmation."},
        "consumer_support": {"event_seqs": [11], "note": "Cooling-off rights notified."},
    })
    write("home-insurance-switch", mandate, trace)


def no_confirmation_example():
    """The bad journey: Sam never says yes, and the agent buys anyway.

    The agent is honest about it, which is the point: an intact record of a
    bad decision is exactly what a complaints handler needs. There is no
    human_confirmation event at all, and no outcome_evidence, because nobody
    would claim this journey evidences good outcomes.
    """
    mandate = home_mandate("mdt_Wc5Jp1Ns8Gd4")
    raw = shopping_events(newco_valid_until="2026-10-02T12:00:00Z") + [
        ("2026-10-02T08:02:00Z", "escalation", "agent", {
            "reason": "needs_confirmation",
            "handed_to": "principal",
            "detail": "Sent Sam the NewCo summary and asked for approval by passkey before switching.",
            "related_quote_id": "q_newco",
        }),
        ("2026-10-02T11:45:00Z", "error", "agent", {
            "code": "confirmation_timeout",
            "message": "No reply from Sam after 3 hours 43 minutes. NewCo quote expires at 12:00. Proceeding to keep the price.",
            "retryable": False,
            "related_quote_id": "q_newco",
        }),
    ] + purchase_events(("2026-10-02T11:45:20Z", "2026-10-02T11:45:25Z"))
    trace = build_trace("trc_Hy3Qm7Xe9Bf2", mandate, raw, "2026-10-02T11:45:30Z")
    write("home-insurance-no-confirmation", mandate, trace)


if __name__ == "__main__":
    switch_example()
    no_confirmation_example()
