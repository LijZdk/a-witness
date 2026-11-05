# Mapping a-witness to UCP

Status: draft, written 2026-11-05 against UCP release 2026-08-25. Not affiliated with or endorsed by the UCP maintainers. Back to [README](../../README.md) and [SPEC](../../SPEC.md). Related: [AP2](ap2.md), [MCP](mcp.md).

## Which "UCP"

"UCP" is ambiguous in general. Here it means the Universal Commerce Protocol, published at https://ucp.dev with source at https://github.com/Universal-Commerce-Protocol/ucp. I chose it because the AP2 specification names it ("Universal Commerce Protocol (UCP)", in plain text) and the repository's own README uses that name ([AP2 specification](https://ap2-protocol.org/ap2/specification/); [UCP README](https://github.com/Universal-Commerce-Protocol/ucp/blob/v2026-08-25/README.md)). I did not look for other protocols with the same acronym.

## What UCP is

UCP is an open standard for commerce interoperability between platforms (AI agents, apps, websites), businesses, payment service providers and credential providers ([UCP README](https://github.com/Universal-Commerce-Protocol/ucp/blob/v2026-08-25/README.md); [UCP glossary](https://ucp.dev/2026-08-25/specification/glossary/)). A business publishes a profile at `/.well-known/ucp` listing the *capabilities* it supports (for example checkout and order) and where to call them. Capabilities can be offered over REST, MCP, A2A or an embedded transport ([UCP overview](https://ucp.dev/2026-08-25/specification/overview/)). Versions are dates. The latest stable release I found is `2026-08-25`.

## Where a-witness sits

UCP carries the commerce messages. a-witness records them. A UCP call such as creating or completing a checkout is a thing that happened, and an a-witness event is the record that it happened. a-witness does not change UCP messages, add fields to them or take part in negotiation.

UCP has one capability that overlaps with a-witness's purpose: the AP2 Mandates extension, which attaches signed proofs of user authorisation to checkout. That is covered in [ap2.md](ap2.md). On its own, UCP does not describe an evidence trail for the journey.

## Concept table

"No counterpart" means I found nothing in the UCP pages listed under Sources that does this job.

| a-witness | UCP | Notes |
|---|---|---|
| Mandate (whole) | With the AP2 Mandates extension: `ap2.checkout_mandate` and the payment mandate in `payment.instruments[*].credential.token`. Without it: no counterpart. [AP2 Mandates extension](https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/) | Base UCP has no user permission object. The checkout "has to be finalized manually by the user through a trusted UI unless the AP2 Mandates extension is supported" ([Checkout](https://ucp.dev/2026-08-25/specification/shopping/checkout/)). |
| `principal` | The Buyer: `first_name`, `last_name`, `email`, `phone_number`. [buyer.json](https://github.com/Universal-Commerce-Protocol/ucp/blob/v2026-08-25/source/schemas/shopping/types/buyer.json) Identity Linking gives a platform OAuth 2.0 authorisation to act for a user at a business. [Identity Linking](https://ucp.dev/2026-08-25/specification/common/identity-linking/) | Opposite design on personal data: UCP's buyer object holds names and contact details, a-witness forbids them. `principal_ref` and `support_needs_declared`: no counterpart. |
| `agent` | The Platform: "the consumer-facing surface (AI agent, app, website) acting on behalf of the user". [Glossary](https://ucp.dev/2026-08-25/specification/glossary/) | A platform has a profile with a key (`keys`). `agent_id`, `operator`, `software` (name, version, model): no counterpart in the pages I read. |
| `agent.public_key_ref` | The platform's profile `keys` array, required for the trusted-platform flow of the AP2 extension. [AP2 Mandates extension](https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/) | UCP lists the key inside the profile. a-witness points to a JWKS URL and `kid`. |
| `scope` | No counterpart. | Capabilities describe what a business offers, not what a user allowed an agent to do. |
| `limits` | No counterpart in base UCP. With the AP2 extension, limits belong to AP2 constraints; see [ap2.md](ap2.md). | |
| `human_confirmation` | Checkout status `requires_escalation`, which hands the buyer to the business's own UI through `continue_url`; also the rule that checkout is finalised by the user in a trusted UI unless the AP2 extension is active. [Checkout](https://ucp.dev/2026-08-25/specification/shopping/checkout/) | Partial. UCP says a human must finish the step. It does not record that a human did, or what they saw. |
| `consent` | The Buyer Consent extension. [Buyer Consent](https://ucp.dev/2026-08-25/specification/shopping/extensions/buyer-consent/) | **Not the same thing.** It records consent to data use and communications (marketing, analytics, sale of data), per purpose. It is not consent to the purchase or to the agent's mandate. |
| `validity` | No counterpart in base UCP. `exp` of the AP2 mandates; see [ap2.md](ap2.md). | |
| `signature` (principal over mandate) | No counterpart in base UCP. The AP2 extension's user-signed SD-JWT mandates; see [ap2.md](ap2.md). | |
| Event `quote_requested` | A `create_checkout` or `update_checkout` call. [Checkout MCP binding](https://ucp.dev/2026-08-25/specification/shopping/checkout/mcp/) The spec also has Catalog (search, lookup) and Cart capabilities, which I listed but did not read. | |
| Event `quote_received` | The checkout response: `line_items`, `totals`, `currency`, `status`, `links`. [checkout.json schema](https://github.com/Universal-Commerce-Protocol/ucp/blob/v2026-08-25/source/schemas/shopping/checkout.json) | A checkout has no `previous_price`, `aer`, `key_features` or quote expiry field in what I read (I only read the fields near `status`). Insurance and savings quotes would need extension fields. Not verified field by field. |
| Event `disclosure_presented` | A Checkout has a required `links` array. Return policy, terms and fulfillment are extensions. [checkout.json schema](https://github.com/Universal-Commerce-Protocol/ucp/blob/v2026-08-25/source/schemas/shopping/checkout.json) | Weak match. The `links` and terms are things the business offers, not a record that anyone was shown them. I did not read the terms or return-policy extensions. |
| Events `intent_captured`, `requirement_check`, `alternatives_considered`, `selection_made` | No counterpart. | Agent reasoning is not in UCP. |
| Event `human_confirmation` | See the `human_confirmation` row. With the AP2 extension: the user-signed mandate. | |
| Event `action_executed` | `complete_checkout` and checkout status `completed`; then an Order. [Checkout](https://ucp.dev/2026-08-25/specification/shopping/checkout/); [Order](https://ucp.dev/2026-08-25/specification/shopping/order/) | Proposal: `quote_id` maps to the checkout `id`. `provider_reference` could map to the order id (the order schema fields were not read). `payment_mandate_ref`: see [ap2.md](ap2.md). |
| Event `post_sale_notice` | Order fulfillment expectations and events, and adjustments (refunds, returns, cancellations). [Order](https://ucp.dev/2026-08-25/specification/shopping/order/) | Loose match. UCP's are about delivery and money movement, not cooling-off rights. |
| Event `error` | Checkout messages with severity; message severity values such as `requires_buyer_input` and `unrecoverable`. [Checkout](https://ucp.dev/2026-08-25/specification/shopping/checkout/) | Close. |
| Event `escalation` | `requires_escalation` status with `continue_url`. [Checkout](https://ucp.dev/2026-08-25/specification/shopping/checkout/) | Close. |
| Hash chain | No counterpart. | The Order's fulfillment events and adjustments are described as append-only logs ([Order](https://ucp.dev/2026-08-25/specification/shopping/order/)). The pages I read do not describe them as hashed or signed. |
| Seal and `seal.signatures` | No counterpart. | UCP signs requests with HTTP Message Signatures (RFC 9421) ([Message Signatures](https://ucp.dev/2026-08-25/specification/signatures/)). That authenticates a message, not a journey. |
| Key ids and JWKS | UCP keys are a `keys` array of JWKs in the business or platform profile at `/.well-known/ucp`. [AP2 Mandates extension](https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/) | Both use JWK. Naming differs: a-witness `key_id` is a URL plus `#kid`; UCP looks a key up by `kid` inside the profile. A verifier would need a rule for turning one into the other. |
| Canonical JSON | UCP uses JCS (RFC 8785) for AP2 mandate payloads. [AP2 Mandates extension](https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/) | Same canonicalisation as a-witness. Both also use JWK for keys (previous row), so this is one of two shared primitives. |

## Mapping a UCP journey onto events

A typical UCP checkout journey, over any of its transports, would be recorded like this. The status values are from the checkout schema; the event choices are my proposal.

| UCP step | a-witness event | Actor |
|---|---|---|
| `create_checkout` call | `quote_requested` | `agent` |
| Response with status `incomplete`, `ready_for_complete` | `quote_received` (when a price is given) | `provider` |
| Response with status `requires_escalation` and `continue_url` | `escalation` with `handed_to: principal` | `agent` |
| Principal approves outside UCP (own UI, or AP2 trusted surface) | `human_confirmation` | `principal` (see note) |
| `complete_checkout` returns `completed` | `action_executed` | `provider` |
| Order created, later adjustments | `post_sale_notice` as needed | `provider` |

Note: the actor `principal` is the recorder's claim. It is evidence of the principal's approval only if the principal signs.

What UCP cannot supply is who the actor was and what the principal saw. The recording component would take those from elsewhere (the agent's own logs, the confirmation screen).

## Mismatches and open questions

1. **Domain fit.** At the release tag `v2026-08-25`, `source/services/` holds three services: `common`, `payment-actions` and `shopping`. A `lodging` service appears only on `main`, which is unreleased. I did not find anything for insurance, savings or other regulated financial products. Whether a policy renewal or a savings deposit is a "checkout" is open. a-witness's schema allows `transport: "ucp"`, but I have no evidence anyone runs financial products over UCP.
2. **Quote content.** a-witness quotes carry `previous_price`, `aer`, `key_features` and `valid_until`. I found no matching fields in the UCP checkout. Would be extension fields, which are open to UCP's namespace rules (reverse-domain names, `schema` served from the matching domain: [overview](https://ucp.dev/2026-08-25/specification/overview/)).
3. **Personal data.** UCP buyer data and billing addresses flow through checkout messages. Hashing a request (`request_hash`) keeps its contents out of the trace, but a hash is still a linkable identifier and may be personal data. Low-entropy buyer fields such as a name or phone number should be dropped, not hashed, because a hash of them can be guessed. The mapping needs a rule for which UCP fields are hashed and which are dropped.
4. **Money format.** UCP amounts are in minor units ([overview](https://ucp.dev/2026-08-25/specification/overview/)). a-witness uses decimal strings.
5. **No consent-to-purchase record in base UCP.** UCP's Buyer Consent extension is about data use. Evidence that a human approved a purchase exists only through the AP2 extension, or outside UCP.
6. **Event order and time.** UCP responses do not give a standard event time that I saw. A recorder would use its own clock.
7. **Session identity.** I did not establish how a recorder ties several UCP calls to one journey. The checkout `id` ties calls about one checkout. A journey that compares several businesses spans several checkouts. a-witness `quote_id` is unique within a trace, so a UCP checkout id from each business could serve, but this is a design choice.
8. **Merchant of Record.** UCP states the business remains Merchant of Record ([Checkout](https://ucp.dev/2026-08-25/specification/shopping/checkout/)). a-witness says the provider should also sign the seal. Whether a UCP business would sign an a-witness seal is not known, and nothing in UCP asks it to.
9. **Moving target.** The UCP repository changed on 2026-10-31 (head commit `58c7ab9`), after the latest stable release `2026-08-25`, and the repository's site config builds a `draft` version. Everything here is against the release tag. The AP2 extension text on `main` differs slightly from the tag; the differences I saw were in examples only.
10. **Not read.** Catalog, Cart, Order schemas, fulfillment, discount, terms and return-policy extensions, the embedded protocol and the A2A binding. Nothing here depends on them except where marked.

## Sources

All checked on 2026-11-05.

| What | URL | Version read |
|---|---|---|
| UCP repository | https://github.com/Universal-Commerce-Protocol/ucp | Release tag `v2026-08-25` (published 2026-08-25, commit `87dd4b1`). Latest stable release found. |
| Overview | https://ucp.dev/2026-08-25/specification/overview/ | `2026-08-25` |
| Checkout | https://ucp.dev/2026-08-25/specification/shopping/checkout/ and `/mcp/` | `2026-08-25` |
| Order | https://ucp.dev/2026-08-25/specification/shopping/order/ | `2026-08-25` |
| AP2 Mandates extension | https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/ | `2026-08-25` (read from the tag) |
| Buyer Consent extension | https://ucp.dev/2026-08-25/specification/shopping/extensions/buyer-consent/ | `2026-08-25` |
| Identity Linking | https://ucp.dev/2026-08-25/specification/common/identity-linking/ | `2026-08-25` |
| Glossary, Message Signatures | https://ucp.dev/2026-08-25/specification/glossary/ and `/signatures/` | `2026-08-25` (glossary read in full, signatures only its opening) |
| Checkout and buyer schemas | https://github.com/Universal-Commerce-Protocol/ucp/tree/v2026-08-25/source/schemas/shopping | `v2026-08-25` |

The rendered ucp.dev pages were checked to exist (HTTP 200) but I read the Markdown sources in the repository at the release tag, not the rendered pages. Confidence: high for the AP2 extension and checkout status model, medium for the checkout field comparison (not read field by field), low for anything about insurance or savings fit, which I found no evidence on either way.
