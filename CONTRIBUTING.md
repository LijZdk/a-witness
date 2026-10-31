# Contributing to a-witness

Thanks for looking. a-witness is an early draft spec, so the most useful help right now is **critique, not code**.

## What helps most

- **Issues that poke holes in the schemas.** Is a field missing, misnamed, or impossible to fill in practice? Would a complaints handler or ombudsman actually be able to read a trace?
- **Domain knowledge.** If you work in insurance distribution, savings, Consumer Duty or compliance, payments, or agent protocols (MCP, A2A, AP2, UCP, ACP), tell us where the model does not match how things really work.
- **New worked examples.** A journey from a different product or a different failure mode makes the spec more concrete.

Please open an issue to discuss anything larger than a typo before writing a pull request. The schemas are the product, so changes to them need a reason.

## Working on the repo

```bash
pip install -r requirements.txt
scripts/check.sh
```

`scripts/check.sh` is exactly what CI runs. It must pass before a pull request is merged.

Ground rules:

- **Never hand-edit files in `examples/`.** They carry a real hash chain, so a hand edit breaks it. Change `scripts/make_examples.py` and run it again; CI fails if the committed examples do not match what the script produces.
- **Keep personal data out.** Examples use fictional, clearly fake people, firms and references. Documents and raw instructions are referenced by hash, never copied in.
- **Plain English.** Schema descriptions and docs are read by non-engineers. Prefer short sentences and avoid jargon where a plain word works.

## Licence of contributions

a-witness is licensed under Apache 2.0. By submitting a contribution you agree it is licensed under the same terms, as set out in section 5 of the [LICENSE](LICENSE).

## Conduct

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
