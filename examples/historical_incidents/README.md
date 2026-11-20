# Historical incident reconstructions

These three YAML scenarios are simplified educational reconstructions of
publicly described failure mechanisms. They run against the offline mock
engine: they do not replay original bytecode, transactions, or historical chain
state, and a verified mock verdict establishes only the modelled behavior.

- `the_dao_2016_reentrancy.yaml`: a simplified reentrant withdrawal model.
- `parity_wallet_2017_initialization.yaml`: a simplified unprotected initializer
  model; it does not reproduce the complete wallet-freeze lifecycle.
- `mango_markets_2022_oracle_manipulation.yaml`: a simplified spot-price lending
  model. Mango Markets ran on Solana; this EVM-style mock is an analogy, not a
  Solana replay or an assertion that the original program is reproduced here.

Run from the repository root:

```sh
PYTHONPATH=. python3 examples/historical_incidents/run_all.py
```

The runner prints each current verifier verdict and writes Markdown findings
only for verified scenarios. Generated findings are local artifacts. Review the
YAML assumptions and the mock models before interpreting any result; these
examples provide no evidence about the safety of a current deployment.
