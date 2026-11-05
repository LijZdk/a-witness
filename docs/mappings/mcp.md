# Mapping a-witness to MCP

Status: draft, written 2026-11-05 against MCP specification version 2026-07-28. Back to [README](../../README.md) and [SPEC](../../SPEC.md). Related: [AP2](ap2.md), [UCP](ucp.md).

## What MCP is

The Model Context Protocol (MCP) is an open protocol that connects AI applications to external tools and data. Hosts (the AI application) run clients, which talk to servers over JSON-RPC 2.0. Servers offer features such as tools, resources and prompts ([MCP specification](https://modelcontextprotocol.io/specification/2026-07-28)). A *tool* is a named operation with an input schema that a model can ask a client to call with `tools/call` ([MCP tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).

## Where a-witness sits

MCP moves the calls. a-witness records them. The Phase 4 middleware in [ROADMAP.md](../../ROADMAP.md) wraps an MCP server's tools and writes trace events when they are called. It sits beside the call, not in the decision path. It does not change tool inputs or outputs, and MCP needs no change.

MCP has no mandate, no signature over messages and no audit trail. The tools page tells clients to "log tool usage for audit purposes" and to prompt for confirmation on sensitive operations, and says there should be a human in the loop with the ability to deny invocations, but it defines no format for either ([MCP tools, Security Considerations and User Interaction Model](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)). That is the gap a-witness fills.

## The version matters

MCP changed shape in the 2026-07-28 revision, and a recorder written for the older shape would be wrong. The changelog lists these changes that affect it ([MCP changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)):

- No sessions and no `Mcp-Session-Id` header. Servers that need state across calls "use explicit, server-minted handles passed as ordinary tool arguments".
- No `initialize` handshake. Each request carries its protocol version and client capabilities in `_meta`.
- Server-to-client requests such as elicitation are replaced by *multi round-trip requests*: the server returns a result with `resultType: "input_required"` and the client retries the call with `inputResponses`. The retry has a different JSON-RPC `id`.
- Every result has a `resultType`, `complete` or `input_required`.
- Roots, Sampling and Logging are deprecated.
- `_meta` carries OpenTelemetry keys (`traceparent`, `tracestate`, `baggage`).

## Producing events from tool calls

At the level of MCP's published primitives, a recorder sees these things for each call ([MCP tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)):

| MCP primitive | What it gives the recorder |
|---|---|
| `tools/call` request: `params.name`, `params.arguments`, `_meta` | Which tool, with what arguments, and the request metadata. |
| Result: `content`, optional `structuredContent`, `isError`, `resultType` | What came back, whether the tool reported a failure, and whether the call needs more input. |
| JSON-RPC error | A protocol failure (unknown tool, malformed request). Distinct from a tool failure, which comes back with `isError: true`. |
| Tool definition: `name`, `description`, `inputSchema`, optional `outputSchema` and `annotations` | A schema to validate arguments and results against. Annotations are untrusted unless the server is trusted. |

MCP does not say what a tool *means*. A tool called `get_quote` and one called `buy` look the same to the protocol. So the middleware needs a configuration that says which tool is which kind of step. The roadmap names three kinds: quote, disclose and bind.

| Tool call (by configured role) | a-witness event | Actor | Fields taken from |
|---|---|---|---|
| Quote request | `quote_requested` | `agent` | `arguments` give `provider_id`, `product_id`. `request_hash` is the hash of the canonical arguments. |
| Quote result | `quote_received` | `provider` | `structuredContent` (preferred), mapped to `price`, `aer`, `key_features` and so on. A free-text `content` cannot be mapped reliably. |
| Disclosure fetch | `disclosure_presented` | `provider` | `document_hash` from the bytes returned. `presented_to` cannot be known from MCP: see mismatches. |
| Binding call | `action_executed` | `provider` | Result gives `provider_reference`, `amount_committed`. The `quote_id` comes from arguments. |
| Result with `isError: true` or a JSON-RPC error | `error` | `provider` or `system` | `code`, `message`, `retryable` from the result; `retryable` is not defined by MCP. |
| Result with `resultType: "input_required"` | Not an event by itself. If the input request is a confirmation, see below. | | |

### Human confirmation over MCP

MCP's way to ask a person is *elicitation*. Under the 2026-07-28 pattern a server answers a tool call with `input_required` and an `elicitation/create` request, and the client retries with the person's answer in `inputResponses` ([MCP tools, Input Required Tool Results](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [MCP elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)). The response has an `action` (the example shows `accept`) and optional `content`.

A recorder could turn this into a `human_confirmation` event. But the answer travels through the *client*, and the client is the agent's host. Nothing in MCP shows that a human, and not the agent, supplied it. The spec asks clients to show a UI that makes clear which server is asking and to let the person decline ([MCP elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)), but it is a requirement on the client, not evidence. SPEC.md rule 9 needs an event whose actor is the `principal`. The honest reading is that an MCP elicitation answer is evidence only if the client that relayed it is trusted, or if the answer carries its own proof (for example a passkey assertion in `content`, which MCP leaves to the application). Form-mode elicitation must not be used to collect payment credentials; URL mode is for those ([MCP elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)).

### Tying calls to one trace

With no sessions, the recorder cannot use a connection to know which calls belong to one journey. Options, none of them specified by MCP:

- A trace id passed as a tool argument (the changelog's "server-minted handle" pattern).
- A trace id in `_meta` under a key with the project's own prefix. MCP reserves keys whose second label is `mcp` or `modelcontextprotocol` ([MCP base protocol, `_meta`](https://modelcontextprotocol.io/specification/2026-07-28/basic)), so an a-witness key would use its own reverse-domain prefix.
- The OpenTelemetry `traceparent` in `_meta`. It identifies a distributed trace, which is not an a-witness trace, but it could be stored as an extra payload field to correlate with other logs.

## Concept table

"No counterpart" means I found nothing in the MCP pages listed under Sources that does this job.

| a-witness | MCP | Notes |
|---|---|---|
| Mandate (whole) | No counterpart. | MCP has authorization for HTTP transports, but I did not read it. Whether it can carry a delegated, limited permission like a mandate is not known to me. |
| `principal` | No counterpart in the messages. | Clients identify themselves (`clientInfo` in `_meta`); nobody identifies the end user. |
| `agent` | `io.modelcontextprotocol/clientInfo` in request `_meta` (name, version). [MCP changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) | Identifies the client software, not the agent, its operator or the model. The server's own identity comes back in `serverInfo`. |
| `agent.public_key_ref` | No counterpart. | |
| `scope`, `limits` | No counterpart. | A server can restrict which tools a caller sees by the authorization presented ([MCP tools, Capabilities](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)). That is an access control the server applies. It is not a signed statement from the principal. |
| `human_confirmation` (mandate field) | The advice that there should be a human in the loop. [MCP tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Advice, not a mechanism with a record. |
| `consent`, `validity`, `signature` | No counterpart. | |
| Events `quote_requested`, `quote_received`, `disclosure_presented`, `action_executed`, `error` | `tools/call` and its result. See the table above. | Needs configuration of tool roles. |
| Event `human_confirmation` | Elicitation via `input_required` and `inputResponses`. | Weak evidence, see above. |
| Events `intent_captured`, `requirement_check`, `alternatives_considered`, `selection_made` | No counterpart. | These happen inside the agent. A server wrapper never sees them. |
| Events `post_sale_notice`, `escalation` | No counterpart in the protocol. A server could return them as tool results. | |
| Event time (`at`) | No counterpart. | I found no timestamp in the request or result envelope. The recorder uses its own clock. |
| Hash chain, seal, signatures | No counterpart. | |
| Key ids and JWKS | No counterpart for message signing. | Not found in the pages read. |
| `journey.transport: "mcp"` | Transport is MCP itself. | See the UCP note below. |

## MCP as a transport for UCP

UCP's capabilities map one to one to MCP tools (`create_checkout`, `update_checkout`, `complete_checkout`, `cancel_checkout`, `get_checkout`) ([UCP checkout MCP binding](https://ucp.dev/2026-08-25/specification/shopping/checkout/mcp/)). For such a journey a recorder on the MCP side can use the UCP tool names as the configuration of roles, and the transport value is a choice between `mcp` and `ucp`. SPEC.md does not say which. The UCP binding also puts an idempotency key in the request `meta` for `complete_checkout`. See [ucp.md](ucp.md).

## Mismatches and open questions

1. **A wrapper sees one side.** A middleware on an MCP *server* sees what the server receives and returns. It does not see what the person was shown, what the agent weighed, or the agent's reasons. Events like `selection_made`, `requirement_check` and `alternatives_considered` must come from the agent (a client-side recorder or an explicit tool). SPEC.md allows the agent to log them, but the Phase 4 description ("wraps an MCP server's tools") covers only provider-side events. Needs a decision.
2. **Who is the actor?** MCP messages do not say whether the agent or the person acted. The recorder assigns the actor from its position, which makes `actor` a claim by the recorder, not a fact from the protocol.
3. **`presented_to`.** `disclosure_presented` has `presented_to: principal | agent_only`. MCP can show that a document was returned to the client, which is `agent_only` at best. Showing it to the person is a host UI matter outside MCP.
4. **Free text results.** Hashing and mapping depend on `structuredContent` and an `outputSchema`. A tool that returns prose in `content` gives the recorder a hash of text it cannot interpret.
5. **Retries and multi-round calls.** An `input_required` round trip produces several requests with different JSON-RPC ids that belong to one logical call. The recorder must join them, using `requestState`, and decide whether an abandoned retry is one event or two. HTTP stream breaks also lose in-flight requests, and clients must reissue them as new requests ([MCP changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)). Hash-chained events cannot be deleted later, so a retry policy is needed before recording.
6. **Canonicalisation of arguments.** `request_hash` needs a canonical form of the arguments. RFC 8785 is the a-witness choice. MCP allows any JSON value in `structuredContent` and any JSON Schema 2020-12 keywords ([MCP changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)); numbers beyond 2^53 or non-strict JSON would fail a-witness's own canonicalisation rules (SPEC.md, Hashing).
7. **Moving spec.** MCP has had five dated revisions since November 2024 and a `draft` directory exists beside 2026-07-28. The recorder should log the protocol version from `_meta` on each call (as an extra payload field), since behaviour differs between versions.
8. **Deprecated logging.** MCP's own Logging feature is deprecated in this revision in favour of stderr logging or OpenTelemetry ([MCP changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)). a-witness traces are a different thing from logs, but readers may confuse them. The docs should say so.
9. **Not read.** The MCP authorization pages, the Streamable HTTP transport details, resources and prompts, the tasks extension, and the full schema. Statements about those are left out.

## Sources

All checked on 2026-11-05.

| What | URL | Version read |
|---|---|---|
| MCP specification (rendered) | https://modelcontextprotocol.io/specification/2026-07-28 and `/server/tools`, `/client/elicitation`, `/basic`, `/changelog` (I confirmed `/server/tools` returns HTTP 200, but read the Markdown sources in the repository) | Specification version `2026-07-28` |
| MCP source repository | https://github.com/modelcontextprotocol/modelcontextprotocol | Release `2026-07-28` (published 2026-07-28, commit `5f5440b`). Latest release found. Docs read from `docs/specification/2026-07-28/` at the default branch (head `3c4d91b`, 2026-11-03). I did not diff against the tag. |
| UCP checkout MCP binding | https://ucp.dev/2026-08-25/specification/shopping/checkout/mcp/ | UCP `2026-08-25` |

Confidence: high for tools, `tools/call`, results, `input_required` and the changelog items. Medium for the elicitation description (I read the opening and capability sections, not the whole page). Low for authorization and message identity, which I did not read.
