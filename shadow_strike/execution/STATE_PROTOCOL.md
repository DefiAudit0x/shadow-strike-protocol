# Execution state units and getters

Scenario inputs (`initial_eth`, `value_eth`) and verifier-visible
`eth_balance_before`, `eth_balance_after`, and `legitimate_entitlement`
are in ETH in both executors. Solidity emits integer wei; ForgeRunner divides
by 10^18 at the parsing boundary (Decimal conversion, then float to match the
mock). This preserves existing condition strings and the mock's floating-point
precision limits. Entitlement follows the mock convention: initial attacker ETH.

Generated tests probe each target with read-only staticcalls after the steps.
The `ss.<alias>.<field>` log protocol supports public getters `owner()`,
`last_caller()` / `lastCaller()`, `replay_count()` / `replayCount()`,
`victim_shares()` / `victimShares()`, and
`attacker_balance()` / `attackerBalance()`. Counts, token balances and shares
are raw getter units, with no ETH conversion. A target integration must expose
these getters in the units its conditions expect (e.g. the price builder's
0.01 threshold is in whole shares). Private storage or arbitrary ERC20 decimal
conventions are not inferred. Missing or reverting getters emit no value, so
verification cannot mistake unavailable state for zero. Addresses are lowercase
hex except the emitted attacker address, normalized to the mock's `attacker`
identity. No caller or ownership value is inferred from transaction intent.

`gas_used` was removed from ExecutionResult, including serialized reports:
neither mock estimates nor default zero represented measured execution gas.
