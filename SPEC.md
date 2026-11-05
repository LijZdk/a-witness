# a-witness specification, draft v0.1

This document explains every field in the two a-witness formats, the **mandate** and the **trace**, and the rules that tie them together. It is written to be read by two audiences at once: a complaints handler or compliance reviewer who wants to know what a field means, and an engineer who wants to produce or verify these documents.

The JSON Schemas in [`schemas/`](schemas/) are the machine-readable definition. Where this document and a schema disagree, that is a bug; please open an issue.

> **Status: draft, not production ready.** Field names may still change before v1.0.

**Contents:** [Words used here](#words-used-here) · [Conventions](#conventions) · [Mandate](#mandate) · [Trace](#trace) · [Event types](#event-types) · [Rules across documents](#rules-across-documents) · [Hashing](#hashing) · [Signatures](#signatures) · [Verifying](#verifying) · [Personal data](#personal-data) · [Versioning](#versioning)

---

## Words used here

| Word | Meaning |
|---|---|
| **Principal** | The person or business the agent acts for. In the examples, Sam and Jo. |
| **Agent** | The AI software acting for the principal. |
| **Operator** | The organisation responsible for running the agent. |
| **Provider** | The firm selling the product: an insurer, a bank. |
| **Mandate** | The permission slip: what the principal allowed the agent to do. |
| **Trace** | The record of one journey: every step from the principal's request to the end. |
| **Event** | One step in a trace, such as a quote arriving or the principal saying yes. |
| **Binding action** | A step that commits the principal: buying, switching, cancelling. Recorded as an `action_executed` event. |
| **Seal** | The signed end of a trace, which fixes its content. |
| **Verifier** | Software or a person checking a trace against its mandate. `scripts/validate.py` is the v0.1 verifier. |

## Conventions

**must** and **should** are used in the sense of [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119): *must* is a requirement, *should* is strong advice that may be ignored for a good reason.

**Data types** used throughout:

| Type | Form | Example | Why |
|---|---|---|---|
| Money | Object: `amount` (decimal string, up to 2 places) and `currency` (ISO 4217 code) | `{"amount": "298.00", "currency": "GBP"}` | Strings avoid floating-point rounding. |
| Percent | Decimal string, up to 2 places | `"4.35"` means 4.35% | Same reason as money. |
| Hash | `sha256:` followed by 64 lowercase hex characters | `sha256:3160ab4c…` | See [Hashing](#hashing). |
| Timestamp | RFC 3339 date-time | `"2026-10-02T08:14:02Z"` | UTC with `Z` is recommended. |
| Identifier | String. Mandate ids start `mdt_` and trace ids `trc_`, followed by 12 to 64 letters or digits | `mdt_7Hq2Lk9Xw3Pz` | Prefixes make ids easy to tell apart in logs. |

**Closed and open objects.** The mandate, the trace and their fixed parts are *closed*: a field not listed here is an error. Event **payloads are open**: a producer may add fields beyond those listed. Extra fields are hashed like any other, and a verifier **must** ignore fields it does not understand. Extension field names should be ASCII (see [Hashing](#hashing)).

**Optional fields** are marked *optional* below. Everything else is required.

---

## Mandate

A mandate records what the principal allowed the agent to do. It is created before the journey starts, signed by the principal's wallet or app, and never changed afterwards. To change permissions, issue a new mandate.

Schema: [`schemas/mandate.schema.json`](schemas/mandate.schema.json). Example: [`examples/home-insurance-switch.mandate.json`](examples/home-insurance-switch.mandate.json).

### Top level

| Field | Meaning |
|---|---|
| `spec_version` | Always `"0.1"` for this draft. |
| `mandate_id` | Unique id for this mandate, e.g. `mdt_7Hq2Lk9Xw3Pz`. |
| `principal` | Who the agent acts for. See below. |
| `agent` | Who is acting. See below. |
| `scope` | Which products and actions are allowed. See below. |
| `limits` | Price, rate, term and must-have limits. See below. |
| `human_confirmation` | When the agent must get a live yes from the principal before a binding action. See below. |
| `consent` | How and when the principal agreed. See below. |
| `validity` | When the mandate starts and stops. See below. |
| `signature` | The principal's signature over the rest of the mandate: its `alg`, `key_id` and `value`. See [Signatures](#signatures). |

### `principal`

Pseudonymous by design. No names, addresses or account numbers belong in a mandate.

| Field | Meaning |
|---|---|
| `principal_ref` | An opaque id only the principal's own wallet, or the provider at the point of sale, can link to a real person. |
| `type` | `consumer`, `sole_trader` or `business`. |
| `jurisdiction` | *Optional.* Two-letter country code. Defaults to `GB`. |
| `support_needs_declared` | *Optional.* `true` if the principal has said they want extra support (what the FCA calls vulnerability). The details are never stored; the flag tells the agent and provider to slow down and offer help. |

### `agent`

| Field | Meaning |
|---|---|
| `agent_id` | Identifier of the agent. |
| `operator` | The organisation or person responsible for running the agent. |
| `software` | *Optional.* `name`, `version` and `model` (the underlying AI model, if known), each optional. Lets a reviewer tell which version of the agent made a decision. |
| `public_key_ref` | *Optional, strongly recommended.* The key id of the key the agent seals traces with, e.g. `https://agent.example/.well-known/jwks.json#home-helper`. When present, the agent's seal signature must use exactly this key, which ties every trace to the agent the principal authorised. |

### `scope`

| Field | Meaning |
|---|---|
| `product_classes` | The kinds of product the agent may deal in, at least one: `motor_insurance`, `home_insurance`, `contents_insurance`, `pet_insurance`, `travel_insurance`, `easy_access_savings`, `fixed_rate_savings`, `current_account`, `personal_loan`, `credit_card`. |
| `allowed_actions` | What the agent may do, at least one: `research`, `quote`, `compare`, `purchase`, `renew`, `switch`, `cancel`, `amend`. |
| `provider_allowlist` | *Optional.* If present, the only providers the agent may deal with. |
| `provider_blocklist` | *Optional.* Providers the agent must not deal with. |

### `limits`

Every limit is optional. Use the ones that fit the product.

| Field | Meaning |
|---|---|
| `max_commitment` | The most money the agent may commit per product, per term. For insurance that is the premium; for savings, the deposit. |
| `max_price_increase_pct` | For renewals: the largest rise over last term's price, as a percentage, before the agent must stop and ask. A number, e.g. `10`. |
| `min_aer` | For savings: the lowest annual equivalent rate the agent may accept, e.g. `"4.00"`. Below this it must stop and ask. |
| `max_term_months` | The longest term the agent may commit to. |
| `max_transactions` | How many binding actions the mandate allows in total. |
| `requirements` | The principal's must-haves. See below. |

Each entry in **`requirements`** has:

| Field | Meaning |
|---|---|
| `id` | Identifier, referred to by `requirement_check` events, e.g. `req_excess`. |
| `text` | The must-have in the principal's own words, kept verbatim so a reviewer can judge whether it was honoured. |
| `machine_check` | *Optional.* A structured version a verifier can check automatically. Leave it out when checking needs judgement or a lookup, as with the banking-licence requirement in the savings example; the agent then explains in the `requirement_check` event how it checked. |

A **`machine_check`** has a `field`, an `op` and a `value`. `field` names a key in the `key_features` of a `quote_received` event. The operators mean:

| `op` | Passes when the quote's feature… |
|---|---|
| `lte` | …is less than or equal to `value`, compared as decimal numbers (decimal strings such as `"200.00"` are allowed on either side) |
| `gte` | …is greater than or equal to `value`, compared the same way |
| `eq` | …is equal to `value` (same JSON value) |
| `includes` | …is an array containing `value` |
| `excludes` | …is an array not containing `value` |

If the feature is missing from `key_features`, the check fails. *v0.1 defines these meanings, but nothing evaluates machine checks yet; that arrives with the Phase 3 verifier.*

### `human_confirmation`

When the agent must get a live yes from the principal before a binding action:

| Value | Meaning |
|---|---|
| `always` | Before every binding action. |
| `above_limits` | Only when the action would go beyond a limit in `limits`. |
| `never` | Never. Allowed by the schema, but a verifier should flag it, because it removes the principal from every decision. |

See [rule 9](#rules-across-documents) for exactly what counts as a yes.

### `consent`

| Field | Meaning |
|---|---|
| `granted_at` | When the principal granted the mandate. |
| `method` | How: `in_app`, `voice`, `written` or `wallet_passkey`. |
| `terms_hash` | Hash of the exact wording the principal saw when agreeing. The wording itself is kept by whoever showed it, and the hash proves which version it was. |
| `language` | *Optional.* Language of that wording. Defaults to `en-GB`. |

### `validity`

| Field | Meaning |
|---|---|
| `not_before` | The mandate is not valid before this time. |
| `expires_at` | The mandate is not valid after this time. |
| `revocation_url` | *Optional.* Where a verifier can check whether the principal has revoked the mandate early. |

---

## Trace

A trace records one journey made under one mandate: what was asked, what was shown, what was chosen and why. Events are added in order as the journey happens, each one chained to the last, and the trace is sealed at the end.

Schema: [`schemas/trace.schema.json`](schemas/trace.schema.json). Example: [`examples/home-insurance-switch.trace.json`](examples/home-insurance-switch.trace.json).

### Top level

| Field | Meaning |
|---|---|
| `spec_version` | Always `"0.1"` for this draft. |
| `trace_id` | Unique id for this trace, e.g. `trc_Rn4Vb8Ty2Mk6`. |
| `mandate_ref` | Which mandate the journey ran under: its `mandate_id` and `mandate_hash`. The hash pins the exact version; see [Hashing](#hashing). |
| `journey` | A summary of the journey. See below. |
| `events` | The steps, in order. At least one. See [Events](#events). |
| `outcome_evidence` | *Optional.* Pointers to the events that evidence each Consumer Duty outcome. See below. |
| `seal` | The signed end of the trace. See below. |

### `journey`

| Field | Meaning |
|---|---|
| `action` | The main thing the journey set out to do, from the same list as `scope.allowed_actions`. |
| `product_class` | The kind of product, from the same list as `scope.product_classes`. |
| `started_at` | When the journey started. Should equal the first event's time. |
| `ended_at` | *Optional.* When it ended. Should equal the last event's time. |
| `status` | *Optional.* `completed`, `abandoned`, `escalated_to_human` or `failed`. |
| `transport` | *Optional.* Which protocol the journey ran over: `mcp`, `a2a`, `ap2`, `ucp`, `acp`, `rest` or `other`. a-witness records journeys on these protocols; it does not replace them. |

### Events

Every event has the same outer fields. What differs by type is the `payload`.

| Field | Meaning |
|---|---|
| `seq` | Position in the trace: 0 for the first event, then 1, 2, 3 with no gaps. |
| `at` | When it happened. Never earlier than the event before. |
| `type` | What kind of step this is. See [Event types](#event-types). |
| `actor` | Who did it: `agent`, `provider`, `principal` or `system`. |
| `payload` | The details, shaped by `type`. |
| `prev_hash` | The previous event's `hash`. For event 0, the mandate hash. This is what chains the events together and to the mandate. |
| `hash` | This event's own hash. See [Hashing](#hashing). |

### `outcome_evidence`

The FCA's Consumer Duty asks firms to show good outcomes in four areas. This optional section points a reviewer at the events that evidence each one. Each of the four keys is optional and holds `event_seqs` (a list of event `seq` numbers) and an optional `note`.

| Key | Consumer Duty outcome | Typical events |
|---|---|---|
| `products_and_services` | The product meets the customer's needs | `requirement_check` |
| `price_and_value` | Fair value | `quote_received` with `previous_price` or `previous_aer`, `alternatives_considered`, `selection_made` |
| `consumer_understanding` | The customer understood what they were getting | `disclosure_presented` before `human_confirmation` |
| `consumer_support` | Support after the sale | `post_sale_notice` |

This section is a **claim, not proof**. Whoever writes it is pointing at their own best evidence. A reviewer should read the events it cites, and the events it does not.

### `seal`

| Field | Meaning |
|---|---|
| `final_event_hash` | The `hash` of the last event, which fixes the entire chain behind it. |
| `sealed_at` | When the trace was sealed. Not earlier than the last event. |
| `signatures` | At least one. Each has a `signer` (`agent`, `provider`, `principal` or `witness_service`), an `alg` (`ES256` or `EdDSA`), a `key_id` and the signature `value`. Each covers the **whole trace** except the signatures themselves. The agent must sign, and the provider should too, so both sides hold the same record. See [Signatures](#signatures). |

---

## Event types

Listed in the order they usually occur. Not every journey uses every type, and types may repeat: one `quote_received` per quote, for example. Fields marked *optional* may be left out; payloads may also carry extra fields (see [Conventions](#conventions)).

### `intent_captured`

What the principal asked for. Usually the first event. Actor: usually `agent`.

| Field | Meaning |
|---|---|
| `summary` | What the principal asked for, in their words or a faithful summary. |
| `utterance_hash` | *Optional.* Hash of the raw instruction, so it can be proved later without being stored. |

### `quote_requested`

The agent asked a provider for a quote. Actor: usually `agent`.

| Field | Meaning |
|---|---|
| `provider_id` | Who was asked. |
| `product_id` | *Optional.* If a specific product was asked for, rather than any match. |
| `request_hash` | *Optional.* Hash of the data sent, which may include personal details, so the request is evidenced without being stored. |

### `quote_received`

A provider offered a product. Actor: usually `provider`. Must have a `price`, an `aer`, or both.

| Field | Meaning |
|---|---|
| `quote_id` | Identifier for this quote, unique within the trace. Later events refer to the quote by it. |
| `provider_id` | Who offered it. |
| `provider_frn` | *Optional.* The provider's FCA Firm Reference Number, so a reviewer can check it on the FCA register. |
| `product_id` | Which product. |
| `price` | *Optional.* What the principal would pay, e.g. an insurance premium. Money. |
| `previous_price` | *Optional.* What the principal paid last term, so a renewal rise is visible. Money. |
| `aer` | *Optional.* The annual equivalent rate the principal would earn, e.g. on savings. Percent. |
| `previous_aer` | *Optional.* The rate the principal earned last term, so a drop at maturity or renewal is visible. Percent. |
| `term_months` | How long the product runs. |
| `key_features` | *Optional.* The product's features as structured data, e.g. `{"excess": "200.00", "cover": ["buildings", "contents"]}`. Requirement `machine_check`s refer to these by name. |
| `valid_until` | *Optional.* When the quote expires. |

### `requirement_check`

The agent checked a quote against the principal's must-haves. Actor: usually `agent`.

| Field | Meaning |
|---|---|
| `quote_id` | Which quote was checked. |
| `results` | One entry per requirement checked: `requirement_id` (from the mandate), `passed` (`true` or `false`) and an optional `detail` explaining how, e.g. `"200.00 <= 250.00"`. |

### `alternatives_considered`

What the agent looked at and why it ruled things out. Actor: usually `agent`.

| Field | Meaning |
|---|---|
| `options` | At least one entry, each with a `quote_id`, `considered` (`true` if the agent actually weighed it) and an optional `excluded_reason` in plain language. |
| `market_coverage_note` | *Optional.* An honest statement of how much of the market was searched, e.g. "3 providers queried. Not whole of market." |

### `disclosure_presented`

A document such as policy terms was shown. Actor: usually `provider`.

| Field | Meaning |
|---|---|
| `document_kind` | `ipid` (insurance product information document), `key_facts`, `terms`, `summary_box` (the standard savings summary), `fee_schedule`, `cancellation_rights` or `other`. |
| `document_hash` | Hash of the exact document, so the version shown can be proved without copying it. |
| `document_url` | *Optional.* Where the document can be found. |
| `presented_to` | `principal` if the principal was shown it, or `agent_only` if only the agent read it. The difference matters for consumer understanding. |
| `plain_summary` | *Optional.* What the agent told the principal about the document. |

### `selection_made`

The agent chose a product. Actor: usually `agent`.

| Field | Meaning |
|---|---|
| `quote_id` | The chosen quote. |
| `rationale` | Why, in plain language. |
| `within_mandate_limits` | *Optional.* The agent's own claim that the choice is within the mandate. A verifier checks this independently and does not rely on it. |

### `human_confirmation`

The principal's answer when asked to approve. Actor: **must** be `principal` to count as their answer.

| Field | Meaning |
|---|---|
| `method` | How they answered: `in_app_tap`, `passkey`, `voice` or `message_reply`. |
| `decision` | `approved`, `declined`, or `modified` (they changed something, so the agent must choose again and ask again). |
| `shown_summary_hash` | *Optional.* Hash of the exact screen or message the principal saw when answering. Strongly recommended: a yes is only as good as what it was a yes to. |

### `action_executed`

The binding action: the purchase, switch or cancellation went through. Actor: usually `provider`.

| Field | Meaning |
|---|---|
| `quote_id` | Which quote was acted on. |
| `provider_reference` | The policy or account reference from the provider. |
| `amount_committed` | How much money was committed. Money. |
| `payment_mandate_ref` | *Optional.* Link to a payment authorisation in another protocol, such as an AP2 payment mandate. |

### `post_sale_notice`

Information given after the sale. Actor: usually `provider`.

| Field | Meaning |
|---|---|
| `notice_kind` | `cancellation_window`, `documents_sent`, `renewal_reminder` or `support_contact`. |
| `detail` | *Optional.* The notice in plain language. |
| `deadline` | *Optional.* For example, when a cooling-off period ends. |

### `escalation`

The agent stopped and handed over instead of carrying on. Actor: usually `agent`.

| Field | Meaning |
|---|---|
| `reason` | `outside_mandate`, `needs_confirmation`, `support_needs`, `provider_referral`, `agent_uncertain` or `other`. |
| `handed_to` | `principal`, `provider_human` or `agent_operator`. |
| `detail` | *Optional.* Plain-language explanation for a reviewer. |
| `related_quote_id` | *Optional.* The quote concerned, if any. |

### `error`

Something went wrong. Recording errors honestly is part of the record: in the `home-insurance-no-confirmation` example, the error event is the agent admitting it gave up waiting for the principal. Actor: any.

| Field | Meaning |
|---|---|
| `code` | Short machine-readable code, e.g. `provider_timeout`. |
| `message` | *Optional.* Plain-language description. |
| `retryable` | *Optional.* Whether trying again could work. |
| `related_quote_id` | *Optional.* The quote concerned, if any. |

---

## Rules across documents

These are the rules no single schema can express. The last column says whether the v0.1 verifier, `scripts/validate.py`, enforces each one. The rest are enforced by the Phase 3 verifier unless noted. The Go reference implementation checks rules 1 to 8 and 15 in `witness.Verify`, and adds the mandate rules in `witness.Check`; the last column says what `Check` covers.

| # | Rule | Checked in v0.1 (`validate.py`) | Checked by Go `witness.Check` |
|---|---|---|---|
| 1 | `mandate_ref.mandate_id` and `mandate_ref.mandate_hash` match the mandate. | Yes | Yes |
| 2 | Event `seq` numbers run 0, 1, 2… with no gaps. | Yes | Yes |
| 3 | Each event's `prev_hash` is the previous event's `hash`; event 0's is the mandate hash. | Yes | Yes |
| 4 | Each event's `hash` matches its content. | Yes | Yes |
| 5 | Event times never go backwards, and `seal.sealed_at` is not before the last event. | Yes | Yes |
| 6 | `seal.final_event_hash` is the last event's `hash`. | Yes | Yes |
| 7 | Every `seq` cited in `outcome_evidence` exists. | Yes | Yes |
| 8 | Every `quote_received` has its own `quote_id`, unique within the trace. Every `quote_id` or `related_quote_id` in another event (including each option in `alternatives_considered`) refers to a `quote_received` earlier in the same trace. | Yes | Yes |
| 9 | **Human confirmation.** When `human_confirmation` is `always`, every `action_executed` needs its own approval: a `human_confirmation` event with actor `principal` and decision `approved`, after the most recent `selection_made`, and the action's `quote_id` must be the selected quote. An approval is used up by one action. A new `selection_made` cancels an earlier approval, because a yes to one choice is not a yes to another, and so does a later `human_confirmation` that is `declined` or `modified`. For `above_limits`, an approval is needed only when the action goes beyond a limit in `limits` (this needs rule 12). | Yes, for `always` only | Yes, for `always`; `above_limits` is reported as not checked |
| 10 | `journey.product_class` is in `scope.product_classes` and `journey.action` is in `scope.allowed_actions`. Further, if `scope.allowed_actions` contains no binding action (`purchase`, `renew`, `switch`, `cancel`, `amend`), no `action_executed` event may appear. `provider_allowlist` and `provider_blocklist` are not covered by any rule yet. | No | Yes, with the extension in the rule; provider lists are not covered |
| 11 | Every event falls inside the mandate's `validity` window (`not_before` and `expires_at`, both inclusive, compared as instants), and the mandate was not revoked. Only the events' `at` times count, not the seal's, consent's or journey's. | No | The window, yes; revocation is reported as not checked |
| 12 | No binding action exceeds `max_commitment`, `max_term_months` or `max_transactions`; no renewal rise exceeds `max_price_increase_pct`; no savings rate falls below `min_aer`. | No | No, reported as not checked |
| 13 | No chosen quote failed a requirement check. | No | No, reported as not checked |
| 14 | `human_confirmation: "never"` is flagged: a warning, not a failure. `above_limits` is enforced (see rule 9). | No | `never` is flagged as a warning; `above_limits` is reported under rule 9 |
| 15 | **Signatures.** The principal's signature on the mandate is valid. Every seal signature is valid. At least one valid seal signature is from the `agent`, and if the mandate names `agent.public_key_ref`, that signature uses exactly that key. Keys must be known to the verifier. | Yes, with `--keys` | Yes, when keys are given |

---

## Hashing

Hashes are what make a trace tamper-evident. They need to be computed identically everywhere, so this section is exact.

### What is hashed

| Hash | Input |
|---|---|
| Mandate hash (`mandate_ref.mandate_hash`, and event 0's `prev_hash`) | The mandate's canonical JSON **without** its `signature` field. Signing a mandate therefore does not change its hash. |
| Event `hash` | The event's canonical JSON **without** its `hash` field. This includes `seq` and `prev_hash`, which is what chains each event to the last. |
| Text and document hashes (`terms_hash`, `utterance_hash`, `document_hash`, `shown_summary_hash`) | The exact bytes of the text or document. For text, the UTF-8 encoding with no normalisation: one changed space gives a different hash. |

Every hash is written as `sha256:` followed by the SHA-256 digest in lowercase hex.

### Canonical JSON

The same JSON value can be written in many ways (key order, spacing), so it is converted to one canonical form before hashing: the JSON Canonicalization Scheme, [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785). In short:

1. Object keys sorted by their UTF-16 code units, at every level.
2. No whitespace: `,` between items and `:` between key and value.
3. Strings escape only the quote, the backslash and control characters. Control characters use the short escapes (`\n`, `\t` and so on) where they exist and `\u00xx` with lowercase hex otherwise. Everything else, including non-ASCII, is literal UTF-8.
4. Numbers are IEEE 754 doubles, written as JavaScript writes them: `1e+21`, `0.000001`, `4.5`.
5. The result encoded as UTF-8.

RFC 8785 is the definition; the list above is a summary. Input must be strict ([I-JSON](https://www.rfc-editor.org/rfc/rfc7493)): an implementation **must** refuse duplicate keys, invalid UTF-8, unpaired surrogate escapes such as `"\ud800"`, and numbers too large for a double. Accepting them would let two different inputs share a hash.

Because numbers are doubles, integers beyond 2<sup>53</sup> lose precision. Money and percentages are strings for this reason, and producers should keep any other numbers small and exact.

Implementations: Go, [`witness/canon`](witness/canon); Python, the [`rfc8785`](https://pypi.org/project/rfc8785/) library via [`scripts/chain.py`](scripts/chain.py).

### Test vectors

[`testdata/vectors/`](testdata/vectors/) holds language-neutral vectors for canonical JSON (including inputs that must be rejected), number formatting, and each kind of hash, with notes on using them. The files in [`examples/`](examples/) are vectors too: an implementation that verifies them is hashing correctly.

### What the chain and the signatures each prove

Changing any event changes its hash, which no longer matches the next event's `prev_hash`, and so on to the seal. A careless edit is therefore caught by the hashes alone. But anyone can edit an event and recompute every hash after it; the hashes cannot stop that. **The signatures can.** Every seal signature covers the whole trace, so any change, to an event, to `journey`, to `outcome_evidence` or to the seal's own fields, means the signatures no longer verify, and a forger cannot re-sign without the signers' private keys.

A signature proves only that the holder of a key signed. That it was *the agent*, *the provider* or *the principal* depends on the verifier trusting that the key belongs to them: see [Keys](#keys).

---

## Signatures

### What is signed

| Signature | Signs | `typ` |
|---|---|---|
| The mandate's `signature`, by the principal | The mandate's canonical JSON **without** its `signature` field: the same bytes as the mandate hash input. | `a-witness-mandate` |
| Each entry in `seal.signatures` | The **whole trace** in canonical JSON, with the `seal` object present but **without** its `signatures` array. This covers `trace_id`, `mandate_ref`, `journey`, every event, `outcome_evidence`, `final_event_hash` and `sealed_at`. | `a-witness-seal` |

Every seal signer signs the same bytes, so signatures do not cover each other and can be added independently and in any order: the agent signs when it closes the journey, the provider when it receives the trace. Nothing but a signature may be added after sealing; in particular, `outcome_evidence` must be written **before** the seal.

### How a signature is made

Each `value` is a detached JWS in compact form ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), appendix F): `header..signature`, with the payload left out because the verifier rebuilds it from the document.

1. The **header** is a JSON object with exactly three members: `alg` (`ES256` or `EdDSA`), `kid` (the signature's `key_id`) and `typ` (from the table above). Implementations should write it in canonical JSON, which makes Ed25519 signatures byte-for-byte reproducible.
2. The **signing input** is `BASE64URL(header) || "." || BASE64URL(payload)`, with base64url as in RFC 7515: no padding.
3. **ES256**: ECDSA on P-256 with SHA-256, the signature being R and S as 32 bytes each (64 bytes, not ASN.1 DER). **EdDSA**: Ed25519 (64 bytes).
4. The `value` is `BASE64URL(header) || ".." || BASE64URL(signature)`.

A verifier **must** refuse a signature whose header has any member besides `alg`, `kid` and `typ`, or whose header values differ from the signature's `alg`, its `key_id` and the expected `typ`. The `typ` check means a mandate signature can never pass as a seal signature.

### Keys

A `key_id` names a public key. The recommended form is a [JWKS](https://www.rfc-editor.org/rfc/rfc7517) URL, `#`, and the key's `kid`: `https://agent.example/.well-known/jwks.json#home-helper`. Keys are EC on P-256 (for ES256) or OKP Ed25519 (for EdDSA).

Which keys to trust for which parties is the verifier's decision, and the most important one it makes. The spec ties one key down itself: the mandate, signed by the principal, names the agent's key in `agent.public_key_ref`, and the agent's seal signature must use it. A verifier should obtain the principal's and provider's keys from a source it trusts, such as the provider's published JWKS or the principal's wallet.

The Go implementation offers a fixed `KeySet` (for example from a local JWKS file, where each key's `kid` is its full `key_id`) and a `JWKSFetcher`, which fetches `https://…#kid` key ids over HTTPS only. `scripts/validate.py` reads a local JWKS file given with `--keys`.

The examples are signed with throwaway Ed25519 keys derived from public strings, published in [`examples/keys.jwks.json`](examples/keys.jwks.json). Anyone can derive their private keys, so the example signatures show the mechanism, not who signed.

---

## Verifying

A verifier answers two separate questions, and reports which one failed:

1. **Is this record genuine?** Schemas, chain, timestamps, references, seal and signatures: rules 1–8 and 15.
2. **Did the agent do what it was allowed to?** The mandate rules: 9–14.

In Go, `witness.Check` answers both, in this order, and its report keeps them apart: integrity problems, rule findings, warnings, and what was not checked. It runs the mandate rules only if the record is intact (question 1 answered yes). It does not yet check the documents against the JSON Schemas (use `scripts/validate.py` for that), and says so in its report; it does return an error for an event whose `type` or `actor` is not one the schema allows. `Pass` is true only if the signatures were checked and valid and the rules ran and found nothing. A warning, such as rule 14's, does not change a pass. A `human_confirmation` event is the agent's record of the principal's yes: unless the seal carries a valid `principal` signature made with the same key that signed the mandate (the mandate signature's `key_id`), that yes is the agent's claim, and the report says so. A `principal` label on a signature made with any other key does not count.

The second question only makes sense once the first is answered yes, because rules checked against a tampered record prove nothing. `scripts/validate.py` reports one of four results:

| Result | Meaning |
|---|---|
| `PASS` | The record is genuine and every rule marked "Yes" in [the table above](#rules-across-documents) is met. The line says if signatures were not checked (no `--keys`) or if the confirmation rule could not be checked for this mandate (any setting but `always`). |
| `FAIL … the record is malformed` | A document does not match its schema. |
| `FAIL … the record is broken or has been tampered with` | The chain, timestamps, references, seal or signatures do not hold together. |
| `FAIL … the record is intact, but the agent broke its mandate` | The record is genuine, and it shows the agent breaking a rule. |

A pass is evidence, not a verdict. It shows the record is intact and the checked rules were followed. Whether the outcome was good for the principal is for firms, ombudsmen and regulators to judge.

---

## Personal data

The formats are designed to keep personal data out:

- Principals appear only as a pseudonymous `principal_ref`.
- Raw instructions, documents, confirmation screens and the data sent to providers are referenced by **hash**, not copied in. Whoever holds the original can prove it matches; the trace alone does not reveal it.
- Free-text fields (`summary`, `plain_summary`, `rationale`, `detail`, `message`, `note`) are meant for a human reviewer and **should not** contain names, contact details, account numbers or health information. Whether to cap or hash these fields is an open question on the [roadmap](ROADMAP.md#open-questions).
- `support_needs_declared` is a yes/no flag only. The reason never belongs in a mandate.

---

## Versioning

- `spec_version` is `"0.1"` for this draft. Any 0.x version may change incompatibly; a verifier should refuse a version it does not know.
- The schemas' `$id` URLs (`https://a-witness.dev/schemas/0.1/…`) are identifiers, not live addresses. They are not yet served from anywhere.
- Changes are discussed in issues first. See [CONTRIBUTING.md](CONTRIBUTING.md).
