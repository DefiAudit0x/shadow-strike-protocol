# Proof, Not Opinion: Building an Execution-Verified Attack Simulator for Smart Contracts

I spent the last few weeks building something I kept wanting to exist every time I read a DeFi post-mortem: a tool that doesn't just *say* a contract is vulnerable, but actually *proves* it — by executing a real attack against real EVM state and checking what happened, not by asking a language model to assert a verdict.

I'm calling it **Shadow Strike Protocol**. This is the thinking behind it, and three historical incidents I used to stress-test the idea.

## The gap I kept running into

After cataloguing 71 documented DeFi incidents (~$6B in losses) for a dataset I published earlier this year, one pattern stood out: almost every post-mortem has the same three-part shape.

1. A hypothesis ("this function is reentrant")
2. An explanation of the mechanism
3. Proof it actually worked — a transaction trace, a before/after balance delta

Most AI-assisted security tooling stops at step 1 or 2. You get "this looks like a reentrancy vulnerability," stated with the confidence of a tool that has never actually tried to exploit anything. That gap — between *describing* a vulnerability class and *demonstrating* this specific instance of it is exploitable — is where false positives live, and it's expensive: every unproven "finding" is a human auditor's time spent re-deriving proof the tool could have produced itself.

## The core design decision

Shadow Strike is built around one non-negotiable separation: **the LLM proposes, the EVM disposes.**

A language model can be excellent at suggesting *where* to look and *what* to try — recognizing that a `call{value: ...}` precedes a state write, say. What it should never do is be the thing that decides whether the attack worked. That decision has to come from executing a real transaction sequence against real (or realistically forked) contract state, then evaluating success conditions against the actual resulting balances and storage — using a restricted expression evaluator, not `eval()`, and absolutely not a model's self-report.

Concretely, every attack in Shadow Strike is a validated data structure (an `AttackScenario`) before it's ever allowed near an EVM: attacker model, initial state, a typed sequence of transaction steps, and — critically — explicit success conditions and invariants, stated as expressions over post-execution state. The scenario gets compiled into a real Foundry test. The test runs. A deterministic verifier checks the conditions against what actually happened. Only then is a finding allowed to exist.

## Does it actually catch anything?

I ran three historical incidents through it, reconstructed from public post-mortems (simplified — not byte-for-byte replays of the original bytecode, see the caveats in the repo):

- **The DAO (2016)** — the reentrancy that split Ethereum and Ethereum Classic. Verified.
- **Parity Multisig Wallet freeze (Nov 2017)** — an unguarded `initWallet()`-equivalent let an attacker become owner of the shared library contract. Verified as an ownership takeover (the scenario stops short of modeling the subsequent `selfdestruct` — more on scope below).
- **Mango Markets (Oct 2022)** — thin-liquidity price manipulation inflating collateral value, then borrowing against it. Verified against a generic AMM-pool mock — worth being honest that the real incident was on Solana, and Shadow Strike is EVM/Foundry-only, so this is a mechanism replay, not a chain-accurate one.

I built a benchmark mode too: point it at a contract, and instead of committing to one hypothesis, it tries every vulnerability class the Attack Library's heuristics flag as plausible, independently, and produces a scorecard. On a synthetic contract with both a reentrancy bug and a broken access-control guard, it correctly flagged one as exploitable and the other as resisted — in one pass.

## What it's honestly not yet

This isn't a finished product, and I'd rather say so than let the demo oversell it:

- Only 7 of 11 vulnerability classes have an automated scenario builder. The other four (accounting errors, upgrade/storage-collision hazards, cross-contract composability bugs, pure economic/game-theoretic attacks) resist genericization — they're inherently specific to the protocol in question. There's a hand-authoring path (write the scenario as YAML, same validation, same pipeline) for exactly this reason.
- The sandboxing is real at the process level (OS resource limits, tested by actually killing a runaway process) but the container-level network isolation is documented, not yet deployed.
- "Continuous monitoring" — auto-rerunning the Attack Library when a protocol upgrades — has working dispatch/alert/regression-detection logic, but the actual on-chain watcher is an interface, not a live poller, because that needs infrastructure this was built without.

## Why this matters beyond one tool

The broader point isn't really about Shadow Strike specifically. It's that "AI finds vulnerabilities" is a claim that should make you ask *how the claim is checked* — and in security tooling specifically, the answer "a model said so" isn't good enough. Execution-verified findings are more expensive to produce than LLM-asserted ones. That cost is the point. It's the same reason a bug bounty submission without a working PoC gets triaged differently than one with one.

If you're building security tooling with an LLM anywhere in the loop, the question worth asking isn't "does it find bugs" — it's "what, specifically, decides whether a finding is real, and can that thing be wrong in a way the system would catch?"

---

*Shadow Strike Protocol is a research-stage project. Code, the three historical-incident reconstructions, and the honesty notes about what's tested versus what's documented-but-unverified are available on request.*
