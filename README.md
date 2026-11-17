# agent-proof

**LIVE: https://sjgant80-hub.github.io/agent-proof/**

The deterministic gate + tamper-evident audit trail for AI agents. **Prove an agent obeyed its
policy and didn't regress — with a receipt that can say FAILS. No LLM judge.**

AI agents are non-deterministic, which is exactly why they die in the pilot: 70% of engineering
leaders name non-determinism their #1 production blocker, and most agent pilots never ship. The
fix the whole field converged on in 2026 — *a generator that proposes, a fresh checker that
reviews, and a deterministic gate that only passes what's actually correct, logged to an audit
trail.* agent-proof is that gate + that trail.

## What it does

- **checkTrace(trace, policy)** — measures an agent run (steps: input → tool calls → output)
  against a policy of **deterministic** rules: allowed / forbidden / required tools, output shape,
  forbidden content, numeric invariants, a step ceiling. Names every violation, with the step. No
  model grades the model.
- **Audit ledger** — every checked run lands on a SHA-256 hash chain. Tamper with any entry and
  the chain breaks visibly. This is what an auditor (or the EU AI Act, whose high-risk logging duty applies from 2 Dec 2027) wants.
- **Regression gate** — run the agent across a fixed scenario suite; certified only if **every**
  scenario obeys the policy. One rogue fails the whole thing. The verdict seals into a
  content-addressed receipt that verifies anywhere — and **FAILS is a first-class receipt.**

The live page runs all of it in your browser (the gated `kernel.mjs`, injected verbatim): check a
clean run and a rogue run, build the audit chain, tamper with it, and prove an agent with a
receipt.

## Why deterministic (the honest wedge)

The market's cheap default is **LLM-as-judge** — a model grading another model. That gives false
confidence; correlated checkers agree for the wrong reasons. agent-proof refuses it. What it
certifies, it certifies deterministically and for real. The trade is explicit: **it proves
compliance and no-regression, not that an answer is subtly "good."** That boundary is the product.

## Run it

```bash
node --test kernel.test.mjs
node tools/witness.mjs mutate kernel.mjs --timeout 20000 --cap 600 --test node --test kernel.test.mjs
node make-page.mjs
```

## Honest limits (v1)

Deterministic policy only (fuzzy judging is deliberately out). Tamper-evident, **not yet
signed/anchored** (Ed25519 issuer signing + external anchor is v2). You bring the trace — wiring
into your agent framework is an adapter, not the kernel. Not audited. Mutation-witnessed in CI
(survivors carry a written equivalence argument). MIT.
