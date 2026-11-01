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

  fixed-rate-savings-switch        PASSES. A different product: Jo's fixed
                                   rate bond is maturing into a poor rollover
                                   rate. The agent moves the money to a better
                                   FSCS protected bond, ruling out a higher
                                   rate that is not protected.

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
            "max_commitment": {"amount": "350.00", "currency": "GBP"},
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


def build_trace(trace_id, mandate, raw_events, sealed_at, provider_key, outcome_evidence=None):
    """Chain the events to the mandate and seal them, signed by the agent and the chosen provider."""
    m_hash = hash_mandate(mandate)
    events = chain_events(m_hash, raw_events)
    trace = {
        "spec_version": "0.1",
        "trace_id": trace_id,
        "mandate_ref": {"mandate_id": mandate["mandate_id"], "mandate_hash": m_hash},
        "journey": {
            "action": "switch",
            "product_class": mandate["scope"]["product_classes"][0],
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
            {"signer": "agent", "alg": "ES256", "key_id": f"{mandate['agent']['agent_id']}#k1", "value": PLACEHOLDER_SIG},
            {"signer": "provider", "alg": "ES256", "key_id": provider_key, "value": PLACEHOLDER_SIG},
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
    trace = build_trace("trc_Rn4Vb8Ty2Mk6", mandate, raw, "2026-10-02T08:14:30Z", "prov_newco#k1", outcome_evidence={
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
    trace = build_trace("trc_Hy3Qm7Xe9Bf2", mandate, raw, "2026-10-02T11:45:30Z", "prov_newco#k1")
    write("home-insurance-no-confirmation", mandate, trace)


def savings_example():
    """A different product: Jo's fixed-rate bond is maturing.

    The incumbent's default is to roll the money into a new bond at a much
    lower rate. The agent finds a better rate, but has to rule out a higher
    one that is not FSCS protected and one that locks the money away for
    too long. Insurance is about what you pay; savings is about what you
    earn, so quotes carry an AER instead of a price.
    """
    mandate_id = "mdt_Fs8Kd2Rw6Tq1"
    mandate = {
        "spec_version": "0.1",
        "mandate_id": mandate_id,
        "principal": {
            "principal_ref": "prn_5d2e7b14",
            "type": "consumer",
            "jurisdiction": "GB",
            "support_needs_declared": False,
        },
        "agent": {
            "agent_id": "agt_savewise_01",
            "operator": "Example Agent Ltd",
            "software": {"name": "save-wise", "version": "1.2.0", "model": "example-model"},
            "public_key_ref": "https://agent.example/.well-known/jwks.json#k2",
        },
        "scope": {
            "product_classes": ["fixed_rate_savings"],
            "allowed_actions": ["quote", "compare", "switch"],
        },
        "limits": {
            "max_commitment": {"amount": "20000.00", "currency": "GBP"},
            "min_aer": "4.00",
            "max_term_months": 24,
            "max_transactions": 1,
            "requirements": [
                {
                    "id": "req_fscs",
                    "text": "Must be protected by the FSCS",
                    "machine_check": {"field": "fscs_protected", "op": "eq", "value": True},
                },
                {
                    # No machine_check: whether two brands share a banking licence
                    # needs judgement and a lookup, so the agent records how it checked.
                    "id": "req_licence",
                    "text": "Not on the same banking licence as my easy access account, so FSCS cover is not shared",
                },
            ],
        },
        "human_confirmation": "always",
        "consent": {
            "granted_at": "2026-10-12T19:00:00Z",
            "method": "in_app",
            "terms_hash": sha_text("I allow my agent to move my maturing fixed rate savings within these limits."),
            "language": "en-GB",
        },
        "validity": {
            "not_before": "2026-10-12T19:00:00Z",
            "expires_at": "2026-10-20T23:59:59Z",
            "revocation_url": f"https://wallet.example/mandates/{mandate_id}/status",
        },
        "signature": {"alg": "ES256", "key_id": "prn_5d2e7b14#wallet", "value": PLACEHOLDER_SIG},
    }

    def bond(quote_id, provider, frn, product, aer, term, fscs, licence, **extra):
        return {
            "quote_id": quote_id, "provider_id": provider, "provider_frn": frn, "product_id": product,
            "aer": aer, "term_months": term, **extra,
            "key_features": {"fscs_protected": fscs, "banking_licence": licence, "interest_paid": "annually"},
        }

    raw = [
        ("2026-10-12T19:05:00Z", "intent_captured", "agent", {
            "summary": "1 year fixed bond with OldBank matures on 20 October. Find a better fixed rate for the 20,000 GBP, no longer than 2 years.",
            "utterance_hash": sha_text("my savings bond is maturing, get me a decent fixed rate, nothing longer than 2 years"),
        }),
        ("2026-10-12T19:05:20Z", "quote_received", "provider",
         bond("q_rollover", "prov_oldbank", "000004", "oldbank_fix12_rollover", "2.10", 12, True, "lic_oldbank",
              previous_aer="4.60")),
        ("2026-10-12T19:05:41Z", "quote_received", "provider",
         bond("q_steady", "prov_steadybank", "000005", "steady_fix24", "4.35", 24, True, "lic_steadybank")),
        ("2026-10-12T19:05:43Z", "quote_received", "provider",
         bond("q_highrate", "prov_highrate", "000006", "highrate_fix24", "4.60", 24, False, "lic_highrate_iom")),
        ("2026-10-12T19:05:45Z", "quote_received", "provider",
         bond("q_longfix", "prov_longfix", "000007", "longfix_fix60", "4.50", 60, True, "lic_longfix")),
        ("2026-10-12T19:06:02Z", "requirement_check", "agent", {
            "quote_id": "q_steady",
            "results": [
                {"requirement_id": "req_fscs", "passed": True},
                {"requirement_id": "req_licence", "passed": True,
                 "detail": "SteadyBank holds its own banking licence, different from the easy access account's (checked against the FCA register)."},
            ],
        }),
        ("2026-10-12T19:06:03Z", "requirement_check", "agent", {
            "quote_id": "q_highrate",
            "results": [
                {"requirement_id": "req_fscs", "passed": False, "detail": "Deposit taker is licensed outside the UK and not covered by the FSCS."},
            ],
        }),
        ("2026-10-12T19:06:10Z", "alternatives_considered", "agent", {
            "options": [
                {"quote_id": "q_rollover", "considered": True, "excluded_reason": "2.10% AER is below the mandate minimum of 4.00%"},
                {"quote_id": "q_steady", "considered": True},
                {"quote_id": "q_highrate", "considered": True, "excluded_reason": "Highest rate, but not FSCS protected"},
                {"quote_id": "q_longfix", "considered": True, "excluded_reason": "60 month term exceeds the mandate maximum of 24"},
            ],
            "market_coverage_note": "4 products from 4 providers via one comparison MCP server. Not whole of market.",
        }),
        ("2026-10-12T19:06:15Z", "disclosure_presented", "provider", {
            "document_kind": "summary_box",
            "document_hash": sha_text("SteadyBank 2 Year Fixed Rate Bond summary box v7"),
            "document_url": "https://steadybank.example/docs/fix24-summary-box.pdf",
            "presented_to": "principal",
            "plain_summary": "4.35% AER fixed for 2 years, interest paid yearly. You cannot withdraw or close early. FSCS protected.",
        }),
        ("2026-10-12T19:06:20Z", "selection_made", "agent", {
            "quote_id": "q_steady",
            "rationale": "Best FSCS protected rate within 2 years. 4.35% instead of the 2.10% rollover: about 450 GBP more interest in the first year.",
            "within_mandate_limits": True,
        }),
        ("2026-10-12T19:21:47Z", "human_confirmation", "principal", {
            "method": "in_app_tap",
            "decision": "approved",
            "shown_summary_hash": sha_text("Open SteadyBank 2 Year Fixed at 4.35% AER with 20,000 GBP from your maturing OldBank bond. No access for 2 years. Approve?"),
        }),
        ("2026-10-12T19:22:05Z", "action_executed", "provider", {
            "quote_id": "q_steady",
            "provider_reference": "SB-FX24-90817",
            "amount_committed": {"amount": "20000.00", "currency": "GBP"},
        }),
        ("2026-10-12T19:22:10Z", "post_sale_notice", "provider", {
            "notice_kind": "cancellation_window",
            "detail": "14 day cooling-off period applies. Funds move from OldBank on maturity, 20 October.",
            "deadline": "2026-10-26T23:59:59Z",
        }),
    ]
    trace = build_trace("trc_Pv6Lc3Zn9Wa5", mandate, raw, "2026-10-12T19:22:15Z", "prov_steadybank#k1", outcome_evidence={
        "products_and_services": {"event_seqs": [5, 6], "note": "Selected bond met both requirements, including FSCS protection."},
        "price_and_value": {"event_seqs": [1, 7, 9], "note": "Low rollover rate caught; best protected rate within the term limit chosen."},
        "consumer_understanding": {"event_seqs": [8, 10], "note": "Summary box shown, including no early access, before confirmation."},
        "consumer_support": {"event_seqs": [12], "note": "Cooling-off rights and maturity date notified."},
    })
    write("fixed-rate-savings-switch", mandate, trace)


if __name__ == "__main__":
    switch_example()
    no_confirmation_example()
    savings_example()
