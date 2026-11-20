"""
shadow_strike.execution.mock_executor
========================================
DRY-RUN / OFFLINE executor. NOT a substitute for ForgeRunner in
production — this is a deliberately small, pure-Python simulation of
ETH transfer + callback semantics, used so that:

  (a) the full Shadow Strike pipeline (scenario -> execute -> verify ->
      proof) can be demonstrated and unit-tested with zero external
      dependencies, no RPC, no Foundry install, no network — and
  (b) new scenario authors get fast (<10ms) feedback on whether their
      *scenario structure* makes sense before paying the cost of a
      real forked-EVM run.

Every ExecutionResult this produces is stamped `engine="mock"` so it
can never be confused with a real Foundry/EVM-verified result
downstream (storage, reporting, the Knowledge Store — everything
checks this field before treating a proof as real).
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field

from shadow_strike.core.models import AttackScenario, ExecutionResult


class MockRevert(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass
class Ledger:
    """Balances for one asset in the simulated world."""
    balances: dict[str, float] = field(default_factory=dict)

    def get(self, alias: str) -> float:
        return self.balances.get(alias, 0.0)

    def move(self, frm: str, to: str, amount: float) -> None:
        if amount <= 0:
            return
        if self.balances.get(frm, 0.0) < amount:
            raise MockRevert(f"insufficient balance: {frm} has {self.balances.get(frm, 0.0)}, needs {amount}")
        self.balances[frm] = self.balances.get(frm, 0.0) - amount
        self.balances[to] = self.balances.get(to, 0.0) + amount

    def transfer(self, frm: str, to: str, amount: float, world: MockWorld) -> None:
        if amount <= 0:
            return
        self.move(frm, to, amount)
        # Simulate the EVM calling the recipient's fallback/receive
        # mid-call — this is precisely the hook reentrancy exploits ride on.
        callee = world.contracts.get(to)
        if callee is not None and hasattr(callee, "on_receive"):
            callee.on_receive(amount, world)


@dataclass
class MockWorld:
    ledger: Ledger
    contracts: dict[str, object] = field(default_factory=dict)
    call_trace: list[dict] = field(default_factory=list)
    token_b_ledger: Ledger = field(default_factory=Ledger)

    def log(self, **kw):
        self.call_trace.append(kw)


# ---------------------------------------------------------------------
# Reference contract models used by the bundled reentrancy demo.
# These intentionally mirror contracts/src/Vault.sol so the *same*
# scenario can be run through the mock executor here, and through the
# real ForgeRunner against the real Solidity, with matching semantics.
# ---------------------------------------------------------------------

class VulnerableVault:
    """Mirrors contracts/src/Vault.sol: withdraw() sends ETH, THEN zeroes
    the internal balance — classic checks-effects-interactions violation."""

    def __init__(self, alias: str):
        self.alias = alias
        self.deposits: dict[str, float] = {}

    def deposit(self, caller: str, world: MockWorld, msg_value: float):
        world.ledger.transfer(caller, self.alias, msg_value, world)
        self.deposits[caller] = self.deposits.get(caller, 0.0) + msg_value
        world.log(contract=self.alias, fn="deposit", caller=caller, value=msg_value)

    def withdraw(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        amount = self.deposits.get(caller, 0.0)
        if amount <= 0:
            raise MockRevert("nothing to withdraw")
        # VULNERABLE ORDER: external call (ETH transfer, which can
        # reenter via on_receive) happens before the state write below.
        world.ledger.transfer(self.alias, caller, amount, world)
        self.deposits[caller] = 0.0   # <-- too late if caller reentered above
        world.log(contract=self.alias, fn="withdraw", caller=caller, amount=amount)


class SafeVault(VulnerableVault):
    """Same interface, correct ordering — provided so the same scenario
    can be re-run against a patched contract to prove the fix holds."""

    def withdraw(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        amount = self.deposits.get(caller, 0.0)
        if amount <= 0:
            raise MockRevert("nothing to withdraw")
        self.deposits[caller] = 0.0   # effects BEFORE interaction — fixed
        world.ledger.transfer(self.alias, caller, amount, world)
        world.log(contract=self.alias, fn="withdraw", caller=caller, amount=amount)


class ReentrantAttacker:
    """Models recursive withdrawals through the receiver callback."""

    def __init__(self, alias: str, target_alias: str, max_reentries: int = 3):
        self.alias = alias
        self.target_alias = target_alias
        self.max_reentries = max_reentries
        self.reentry_count = 0

    def attack(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        vault = world.contracts[self.target_alias]
        if msg_value > 0:
            vault.deposit(self.alias, world, msg_value)
        vault.withdraw(self.alias, world)
        world.log(contract=self.alias, fn="attack", caller=caller)

    def on_receive(self, amount: float, world: MockWorld):
        vault = world.contracts[self.target_alias]
        if (
            self.reentry_count < self.max_reentries
            and vault.deposits.get(self.alias, 0) > 0
            and world.ledger.get(self.target_alias) >= amount
        ):
            # mirrors the Solidity receive() guard: only reenter while the
            # vault still appears to have funds AND we haven't hit the cap
            self.reentry_count += 1
            try:
                vault.withdraw(self.alias, world)
            except MockRevert:
                pass


class MockFlashLender:
    """Mirrors attack_library/flash_loan's ERC-3156-style provider: lends
    `amount`, calls the borrower's onFlashLoan(amount, fee, world), then
    REQUIRES the borrower's ledger-visible repayment before the call
    returns successfully — exactly the atomicity real flash loans enforce
    (borrow and repayment-or-revert happen in one transaction)."""

    def __init__(self, alias: str, fee_bps: float = 0.0):
        self.alias = alias
        self.fee_bps = fee_bps

    def flashLoan(self, caller: str, world: MockWorld, msg_value: float = 0.0, amount: float = 0.0):
        if amount <= 0:
            raise MockRevert("flash loan amount must be positive")
        if world.ledger.get(self.alias) < amount:
            raise MockRevert(f"lender has insufficient liquidity: {world.ledger.get(self.alias)} < {amount}")

        balance_before = world.ledger.get(self.alias)
        fee = amount * self.fee_bps / 10000
        world.ledger.balances[self.alias] -= amount
        world.ledger.balances[caller] = world.ledger.balances.get(caller, 0.0) + amount

        borrower = world.contracts.get(caller)
        if borrower is None or not hasattr(borrower, "onFlashLoan"):
            raise MockRevert(f"{caller} has no onFlashLoan callback — not a valid flash-loan receiver")
        borrower.onFlashLoan(amount, fee, world)

        if world.ledger.get(self.alias) < balance_before + fee:
            raise MockRevert(
                f"flash loan not repaid with fee: lender has {world.ledger.get(self.alias)}, "
                f"needs >= {balance_before + fee}"
            )
        world.log(contract=self.alias, fn="flashLoan", caller=caller, amount=amount, fee=fee)


class FlashLoanReentrantAttacker:
    """Composes flash_loan WITH reentrancy, per attack_library's
    composes_with design (see flash_loan/meta.yaml): the attacker needs
    ZERO starting capital — borrows the deposit stake atomically, uses
    it to set up the same reentrant-withdraw pattern as ReentrantAttacker,
    then repays the loan out of the drained proceeds."""

    def __init__(self, alias: str, lender_alias: str, vault_alias: str, max_reentries: int = 3):
        self.alias = alias
        self.lender_alias = lender_alias
        self.vault_alias = vault_alias
        self.max_reentries = max_reentries
        self.reentry_count = 0

    def attack(self, caller: str, world: MockWorld, msg_value: float = 0.0, borrow_amount: float = 0.0):
        lender = world.contracts[self.lender_alias]
        lender.flashLoan(self.alias, world, amount=borrow_amount)
        world.log(contract=self.alias, fn="attack", caller=caller, borrow_amount=borrow_amount)

    def onFlashLoan(self, amount: float, fee: float, world: MockWorld):
        vault = world.contracts[self.vault_alias]
        vault.deposit(self.alias, world, msg_value=amount)
        vault.withdraw(self.alias, world)   # reentrant drain happens inside, via on_receive below
        world.ledger.transfer(self.alias, self.lender_alias, amount + fee, world)

    def on_receive(self, amount: float, world: MockWorld):
        vault = world.contracts[self.vault_alias]
        if self.reentry_count < self.max_reentries and world.ledger.get(self.vault_alias) >= amount:
            self.reentry_count += 1
            try:
                vault.withdraw(self.alias, world)
            except MockRevert:
                pass


class InitializableTarget:
    """Mirrors attack_library/initialization: an upgradeable-style
    contract whose initialize() has no access restriction — anyone can
    call it (once, since a naive implementation still only allows a
    single call) and become the privileged owner. This is the exact
    shape of the real Parity multisig wallet library freeze (Nov 2017):
    an unprotected initWallet()-equivalent let an attacker become
    owner of the shared library contract, then self-destruct it."""

    def __init__(self, alias: str):
        self.alias = alias
        self.initialized = False
        self.owner: str | None = None

    def initialize(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        if self.initialized:
            raise MockRevert("already initialized")
        self.initialized = True
        self.owner = caller
        world.log(contract=self.alias, fn="initialize", caller=caller)

    def state_vars(self) -> dict:
        return {"initialized": self.initialized, "owner": self.owner}


class AccessControlTarget:
    """Mirrors a privileged function guarded by a broken (or missing)
    access check — `owner` is set at construction but `privilegedAction`
    forgets to verify the caller, matching attack_library/access_control."""

    def __init__(self, alias: str, owner: str = "deployer", enforce_check: bool = False):
        self.alias = alias
        self.owner = owner
        self.enforce_check = enforce_check
        self.privileged_state = 0
        self.last_caller: str | None = None

    def privilegedAction(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        if self.enforce_check and caller != self.owner:
            raise MockRevert(f"caller {caller} is not owner {self.owner}")
        self.privileged_state += 1
        self.last_caller = caller
        world.log(contract=self.alias, fn="privilegedAction", caller=caller)

    def state_vars(self) -> dict:
        return {"last_caller": self.last_caller, "privileged_state": self.privileged_state}


class SimplePool:
    """Constant-product AMM pool (x*y=k) — price is reserve_b / reserve_a.
    A single large swap moves the spot price a lot in one block, which is
    exactly the manipulation surface oracle_manipulation targets."""

    def __init__(self, alias: str, reserve_a: float, reserve_b: float):
        self.alias = alias
        self.reserve_a = reserve_a
        self.reserve_b = reserve_b

    def spot_price(self) -> float:
        """Price of token B in terms of token A (think: ETH per TOKEN, if
        reserve_a is the ETH side). Buying B with A (swapAForB) drains
        reserve_b and adds to reserve_a, which correctly RAISES this —
        exactly the "I bought the token, now it looks more valuable"
        manipulation this attack class targets."""
        return self.reserve_a / self.reserve_b if self.reserve_b else 0.0

    def swapAForB(self, caller: str, world: MockWorld, msg_value: float = 0.0, amount_a: float | None = None):
        amount_a = amount_a if amount_a is not None else msg_value
        if amount_a <= 0:
            raise MockRevert("swap amount must be positive")
        # x*y=k, no fee, for simplicity
        k = self.reserve_a * self.reserve_b
        new_reserve_a = self.reserve_a + amount_a
        new_reserve_b = k / new_reserve_a
        amount_b_out = self.reserve_b - new_reserve_b
        self.reserve_a, self.reserve_b = new_reserve_a, new_reserve_b
        world.ledger.move(caller, self.alias, amount_a)
        world.token_b_ledger.move(self.alias, caller, amount_b_out)
        world.log(contract=self.alias, fn="swapAForB", caller=caller, amount_a=amount_a, amount_b_out=amount_b_out)
        return amount_b_out


class OracleFedLendingMarket:
    """Reads SimplePool.spot_price() directly (the vulnerability) to value
    collateral and decide how much the attacker can borrow against it."""

    def __init__(self, alias: str, pool: SimplePool, reserve_eth: float = 0.0):
        self.alias = alias
        self.pool = pool
        self.reserve_eth = reserve_eth
        self.collateral: dict[str, float] = {}

    def depositCollateral(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        self.collateral[caller] = self.collateral.get(caller, 0.0) + msg_value
        world.ledger.transfer(caller, self.alias, msg_value, world)
        world.log(contract=self.alias, fn="depositCollateral", caller=caller, amount=msg_value)

    def borrowAgainstCollateral(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        # borrows up to (collateral_in_tokenA * current spot price) worth of ETH —
        # the manipulated spot price directly inflates what the attacker can borrow
        collateral_value = self.collateral.get(caller, 0.0) * self.pool.spot_price()
        borrowable = min(collateral_value, self.reserve_eth)
        if borrowable <= 0:
            raise MockRevert("nothing borrowable")
        self.reserve_eth -= borrowable
        world.ledger.balances[self.alias] = self.reserve_eth
        world.ledger.balances[caller] = world.ledger.balances.get(caller, 0.0) + borrowable
        callee = world.contracts.get(caller)
        if callee is not None and hasattr(callee, "on_receive"):
            callee.on_receive(borrowable, world)
        world.log(contract=self.alias, fn="borrowAgainstCollateral", caller=caller, borrowed=borrowable)


class OracleManipulationAttacker:
    """Models oracle manipulation: swap to move the pool's spot price, then borrow against inflated
    collateral valuation, all within one logical "transaction"."""

    def __init__(self, alias: str, pool_alias: str, market_alias: str):
        self.alias = alias
        self.pool_alias = pool_alias
        self.market_alias = market_alias

    def attack(self, caller: str, world: MockWorld, msg_value: float = 0.0, swap_amount: float | None = None):
        pool = world.contracts[self.pool_alias]
        market = world.contracts[self.market_alias]
        swap_amount = swap_amount if swap_amount is not None else msg_value
        tokens_received = pool.swapAForB(self.alias, world, amount_a=swap_amount)
        # the manipulation: deposit the tokens JUST bought as collateral,
        # then immediately borrow against them while the pool still shows
        # the manipulated (post-swap) price — same block, same tx, no
        # window for the price to correct. This is the actual exploit
        # shape (buy -> deposit -> borrow -> profit), not a disconnected
        # fixed collateral amount.
        world.token_b_ledger.move(self.alias, self.market_alias, tokens_received)
        market.collateral[self.alias] = market.collateral.get(self.alias, 0.0) + tokens_received
        market.borrowAgainstCollateral(self.alias, world)
        world.log(contract=self.alias, fn="attack", caller=caller, tokens_received=tokens_received)


class SignedActionTarget:
    """Mirrors attack_library/signature_replay: accepts a pre-authorized
    action identified by a bare signature_id (standing in for a real
    (v,r,s) + payload hash) with no used-signature tracking."""

    def __init__(self, alias: str, track_used: bool = False):
        self.alias = alias
        self.track_used = track_used
        self.used_signatures: set[str] = set()
        self.replay_count = 0

    def executeSignedAction(self, caller: str, world: MockWorld, msg_value: float = 0.0,
                             signature_id: str = "sig-1"):
        if self.track_used and signature_id in self.used_signatures:
            raise MockRevert(f"signature {signature_id} already used")
        self.used_signatures.add(signature_id)
        self.replay_count += 1
        world.log(contract=self.alias, fn="executeSignedAction", caller=caller, signature_id=signature_id)

    def state_vars(self) -> dict:
        return {"replay_count": self.replay_count, "unique_signatures_used": len(self.used_signatures)}


class SignatureReplayer:
    """Models signature replay: submits the SAME signature_id N times."""

    def __init__(self, alias: str, target_alias: str, times: int = 3):
        self.alias = alias
        self.target_alias = target_alias
        self.times = times

    def replay(self, caller: str, world: MockWorld, msg_value: float = 0.0, signature_id: str = "sig-1"):
        target = world.contracts[self.target_alias]
        for _ in range(self.times):
            target.executeSignedAction(self.alias, world, signature_id=signature_id)
        world.log(contract=self.alias, fn="replay", caller=caller, times=self.times)


class ERC4626LikeVault:
    """Mirrors attack_library/price_manipulation: share price = totalAssets/
    totalShares, vulnerable to the classic first-depositor donation attack
    unless donation_resistant=True (simulating e.g. OpenZeppelin's virtual
    shares/decimals-offset mitigation)."""

    def __init__(self, alias: str, donation_resistant: bool = False):
        self.alias = alias
        self.donation_resistant = donation_resistant
        self.total_assets = 0.0
        self.total_shares = 0.0
        self.shares_of: dict[str, float] = {}
        # the offset a donation-resistant implementation effectively adds
        # to totalShares before computing the ratio — defeats the "shares
        # round to zero" attack by making the attacker's donation move the
        # ratio far less than it would against a zero/near-zero base.
        self._virtual_offset = 1_000_000.0 if donation_resistant else 0.0

    def deposit(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        shares = self._convert_to_shares(msg_value)
        world.ledger.transfer(caller, self.alias, msg_value, world)
        self.total_assets += msg_value
        self.total_shares += shares
        self.shares_of[caller] = self.shares_of.get(caller, 0.0) + shares
        world.log(contract=self.alias, fn="deposit", caller=caller, amount=msg_value, shares=shares)

    def donate(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        """Direct token transfer to the vault — inflates total_assets with
        NO shares minted. The actual attack vector: donate() isn't a real
        function, this models sending the underlying asset straight to the
        vault's balance, bypassing deposit() accounting entirely."""
        world.ledger.transfer(caller, self.alias, msg_value, world)
        self.total_assets += msg_value
        world.log(contract=self.alias, fn="donate", caller=caller, amount=msg_value)

    def _convert_to_shares(self, assets: float) -> float:
        effective_shares_base = self.total_shares + self._virtual_offset
        effective_assets_base = self.total_assets + (1.0 if self.donation_resistant else 0.0)
        if effective_shares_base == 0 or self.total_shares == 0:
            return assets  # first depositor, 1:1
        return assets * effective_shares_base / effective_assets_base

    def state_vars(self) -> dict:
        return {
            "total_assets": self.total_assets,
            "total_shares": self.total_shares,
            "victim_shares": self.shares_of.get("victim", 0.0),
        }


class ShareInflationAttacker:
    """Models share inflation: deposit the minimum first, then donate a large amount directly,
    inflating the share price before a victim's deposit lands."""

    def __init__(self, alias: str, vault_alias: str):
        self.alias = alias
        self.vault_alias = vault_alias

    def attack(self, caller: str, world: MockWorld, msg_value: float = 0.0, donation_amount: float | None = None):
        vault = world.contracts[self.vault_alias]
        vault.deposit(self.alias, world, msg_value=1e-9)  # minimal seed deposit, 1 share
        donation_amount = donation_amount if donation_amount is not None else msg_value
        vault.donate(self.alias, world, msg_value=donation_amount)
        world.log(contract=self.alias, fn="attack", caller=caller, donation=donation_amount)


class UncheckedBalanceToken:
    """A worked example for the `accounting` class, which — per
    attack_library/accounting/meta.yaml — deliberately has NO automated
    scenario_planner builder (accounting bugs are too protocol-specific
    to genericize). This is the hand-authoring path in action: a bespoke
    mock for ONE concrete accounting bug, not a reusable template.

    Models the classic unchecked-arithmetic underflow: transfer()
    subtracts from the sender's balance without checking it won't go
    negative. In real pre-0.8 Solidity (or an explicit `unchecked {}`
    block), uint256 underflow wraps around to a near-2^256 value. We
    simulate that wraparound explicitly here since Python has no native
    uint256 semantics to fall back on."""

    UINT256_MOD = 2 ** 256

    def __init__(self, alias: str, checked: bool = False):
        self.alias = alias
        self.checked = checked
        self.balances: dict[str, int] = {}

    def mint(self, caller: str, world: MockWorld, msg_value: float = 0.0, to: str = "", amount: int = 0):
        to = to or caller
        self.balances[to] = self.balances.get(to, 0) + int(amount)
        world.log(contract=self.alias, fn="mint", caller=caller, to=to, amount=amount)

    def transfer(self, caller: str, world: MockWorld, msg_value: float = 0.0, to: str = "", amount: int = 0):
        amount = int(amount)
        bal = self.balances.get(caller, 0)
        if self.checked and bal < amount:
            raise MockRevert(f"transfer amount {amount} exceeds balance {bal}")
        new_bal = (bal - amount) % self.UINT256_MOD   # wraps on underflow, exactly like unchecked uint256
        self.balances[caller] = new_bal
        self.balances[to] = self.balances.get(to, 0) + amount
        world.log(contract=self.alias, fn="transfer", caller=caller, to=to, amount=amount, resulting_balance=new_bal)

    def state_vars(self) -> dict:
        return {"attacker_balance": self.balances.get("attacker", 0)}


class TrustingRouter:
    """Worked example for `cross_contract` — per
    attack_library/cross_contract/meta.yaml, this class has NO automated
    builder by design (the vulnerability is defined by the RELATIONSHIP
    between specific contracts, not a structural property one template
    could cover). Models a router that lets ANYONE repoint which
    contract it trusts for authorization decisions, then blindly acts
    on whatever that trusted contract reports — the bug isn't in this
    contract's arithmetic or guards, it's in WHO it was tricked into
    trusting."""

    def __init__(self, alias: str, pool_balance: float = 50.0):
        self.alias = alias
        self.trusted_computer: str | None = "legitimate_computer"
        self.pool_balance_hint = pool_balance   # for scenario authors wiring initial_state.balances

    def setTrustedComputer(self, caller: str, world: MockWorld, msg_value: float = 0.0, trusted: str = ""):
        # THE BUG: no access control on who can repoint trust
        self.trusted_computer = trusted
        world.log(contract=self.alias, fn="setTrustedComputer", caller=caller, trusted=trusted)

    def withdraw(self, caller: str, world: MockWorld, msg_value: float = 0.0, amount: float = 0.0):
        computer = world.contracts.get(self.trusted_computer)
        if computer is None:
            raise MockRevert(f"trusted computer {self.trusted_computer!r} not found")
        authorized = computer.computeAuthorizedAmount(caller, world)
        if amount > authorized:
            raise MockRevert(f"requested {amount} exceeds authorized {authorized}")
        world.ledger.transfer(self.alias, caller, amount, world)
        world.log(contract=self.alias, fn="withdraw", caller=caller, amount=amount, authorized_by=self.trusted_computer)


class LegitimateComputer:
    """The router's intended dependency — computes a real, bounded
    authorization amount."""

    def __init__(self, alias: str, cap: float = 1.0):
        self.alias = alias
        self.cap = cap

    def computeAuthorizedAmount(self, caller: str, world: MockWorld) -> float:
        return self.cap


class MaliciousComputer:
    """What the attacker redirects trust to — always authorizes
    whatever the router asks, because the attacker controls this
    contract's code entirely."""

    def __init__(self, alias: str):
        self.alias = alias

    def computeAuthorizedAmount(self, caller: str, world: MockWorld) -> float:
        return float("inf")


class VulnerableProxy:
    """Worked example for `upgradeability` — per
    attack_library/upgradeability/meta.yaml, no automated builder by
    design (exploiting a storage collision requires knowing the
    SPECIFIC layout mismatch, which can't be genericized). Models an
    upgradeTo() with no access control; the storage collision itself is
    modeled directly (a malicious implementation's delegatecall-style
    `run()` writes straight to the proxy's `owner` attribute — the
    simplified Python equivalent of a mismatched Solidity storage slot
    landing on the wrong variable)."""

    def __init__(self, alias: str):
        self.alias = alias
        self.owner = "deployer"
        self.implementation: str | None = None

    def upgradeTo(self, caller: str, world: MockWorld, msg_value: float = 0.0, new_impl: str = ""):
        # THE BUG: no access control on who can repoint the implementation
        self.implementation = new_impl
        world.log(contract=self.alias, fn="upgradeTo", caller=caller, new_impl=new_impl)

    def delegateCall(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        impl = world.contracts.get(self.implementation)
        if impl is None:
            raise MockRevert(f"implementation {self.implementation!r} not found")
        impl.run(self, caller, world)
        world.log(contract=self.alias, fn="delegateCall", caller=caller, via=self.implementation)

    def state_vars(self) -> dict:
        return {"owner": self.owner, "implementation": self.implementation}


class MaliciousImplementation:
    """A storage-layout-colliding implementation: its first declared
    variable lands on the proxy's slot 0 (owner), exactly like a real
    Solidity storage collision — except here it's modeled directly as
    writing proxy.owner, to keep the mechanism legible without a full
    slot-indexed storage simulation."""

    def __init__(self, alias: str):
        self.alias = alias

    def run(self, proxy: VulnerableProxy, caller: str, world: MockWorld):
        proxy.owner = caller   # the collision: this contract's own var0 overwrites the proxy's owner slot


class SelfLiquidationMarket:
    """Worked example for `economic` — per
    attack_library/economic/meta.yaml, no automated builder by design
    (these are protocol-specific incentive-design statements, not
    structural code bugs). Models a lending market whose liquidation
    bonus is generous enough that a user can profitably liquidate their
    OWN under-collateralized-by-design position — no price manipulation,
    no code bug, just incentive math that pays more than the risk
    actually costs."""

    def __init__(self, alias: str, liquidation_bonus_bps: float = 1500.0):
        self.alias = alias
        self.liquidation_bonus_bps = liquidation_bonus_bps
        self.collateral: dict[str, float] = {}
        self.debt: dict[str, float] = {}

    def openPosition(self, caller: str, world: MockWorld, msg_value: float = 0.0,
                      collateral_amt: float = 0.0, debt_amt: float = 0.0):
        self.collateral[caller] = collateral_amt
        self.debt[caller] = debt_amt
        world.ledger.transfer(caller, self.alias, collateral_amt, world)
        world.ledger.transfer(self.alias, caller, debt_amt, world)
        world.log(contract=self.alias, fn="openPosition", caller=caller, collateral=collateral_amt, debt=debt_amt)

    def selfLiquidate(self, caller: str, world: MockWorld, msg_value: float = 0.0):
        debt_amt = self.debt.get(caller, 0.0)
        collateral_amt = self.collateral.get(caller, 0.0)
        if debt_amt <= 0:
            raise MockRevert("no debt to liquidate")
        # liquidator (= attacker themselves) repays the debt, receives
        # collateral + bonus. Deliberately NOT capped at the attacker's
        # own `collateral_amt` here — that cap would make the formula
        # structurally incapable of ever exceeding what the attacker put
        # in, which defeats the entire point of this scenario. A real
        # protocol pays the bonus out of its pooled liquidity (other
        # depositors' funds), so the only real cap is what the market
        # actually has on hand — enforced naturally by Ledger.transfer's
        # insufficient-balance check below, not by this formula.
        payout = debt_amt * (1 + self.liquidation_bonus_bps / 10000)
        world.ledger.transfer(caller, self.alias, debt_amt, world)   # repay debt
        world.ledger.transfer(self.alias, caller, payout, world)      # receive collateral + bonus from pooled liquidity
        self.debt[caller] = 0.0
        self.collateral[caller] = max(collateral_amt - payout, 0.0)
        world.log(contract=self.alias, fn="selfLiquidate", caller=caller, debt_repaid=debt_amt, payout=payout)


CONTRACT_REGISTRY = {
    "VulnerableVault": VulnerableVault,
    "SafeVault": SafeVault,
    "ReentrantAttacker": ReentrantAttacker,
    "AccessControlTarget": AccessControlTarget,
    "InitializableTarget": InitializableTarget,
    "SimplePool": SimplePool,
    "OracleFedLendingMarket": OracleFedLendingMarket,
    "OracleManipulationAttacker": OracleManipulationAttacker,
    "SignedActionTarget": SignedActionTarget,
    "SignatureReplayer": SignatureReplayer,
    "ERC4626LikeVault": ERC4626LikeVault,
    "ShareInflationAttacker": ShareInflationAttacker,
    "MockFlashLender": MockFlashLender,
    "FlashLoanReentrantAttacker": FlashLoanReentrantAttacker,
    "UncheckedBalanceToken": UncheckedBalanceToken,
    "TrustingRouter": TrustingRouter,
    "LegitimateComputer": LegitimateComputer,
    "MaliciousComputer": MaliciousComputer,
    "VulnerableProxy": VulnerableProxy,
    "MaliciousImplementation": MaliciousImplementation,
    "SelfLiquidationMarket": SelfLiquidationMarket,
}


class MockExecutor:
    """Drives an AttackScenario through the in-memory world model above."""

    def __init__(self, contract_kinds: dict[str, str], contract_params: dict[str, dict] | None = None):
        """contract_kinds: alias -> key into CONTRACT_REGISTRY, e.g.
        {"vault": "VulnerableVault", "attacker": "ReentrantAttacker"}
        contract_params: alias -> extra constructor kwargs for contracts
        that need more than just their own alias (pools, markets, ...).
        """
        self.contract_kinds = contract_kinds
        self.contract_params = contract_params or {}

    def execute(self, scenario: AttackScenario) -> ExecutionResult:
        ledger = Ledger()
        world = MockWorld(ledger=ledger)

        # two passes: (1) instantiate everything with no cross-contract refs,
        # (2) wire up contracts that reference other contracts (pool, market)
        pending_refs = {}
        for alias, kind in self.contract_kinds.items():
            cls = CONTRACT_REGISTRY[kind]
            params = dict(self.contract_params.get(alias, {}))
            if cls is ReentrantAttacker:
                target_alias = next(
                    a for a, k in self.contract_kinds.items()
                    if k not in ("ReentrantAttacker", "OracleManipulationAttacker")
                )
                # Part 9: the scenario carries the critic-adjusted reentry
                # depth; the default (3) matches AttackScenario's default.
                world.contracts[alias] = ReentrantAttacker(
                    alias, target_alias, max_reentries=scenario.attacker_max_reentries,
                )
            elif cls is SimplePool:
                world.contracts[alias] = SimplePool(
                    alias,
                    reserve_a=params.get("reserve_a", 1000.0),
                    reserve_b=params.get("reserve_b", 1000.0),
                )
            elif cls is OracleFedLendingMarket:
                pending_refs[alias] = ("market", params)
            elif cls is OracleManipulationAttacker:
                pending_refs[alias] = ("oracle_attacker", params)
            elif cls is SignatureReplayer:
                pending_refs[alias] = ("sig_replayer", params)
            elif cls is ShareInflationAttacker:
                pending_refs[alias] = ("share_inflation_attacker", params)
            elif cls is SignedActionTarget:
                world.contracts[alias] = SignedActionTarget(alias, track_used=params.get("track_used", False))
            elif cls is ERC4626LikeVault:
                world.contracts[alias] = ERC4626LikeVault(alias, donation_resistant=params.get("donation_resistant", False))
            elif cls is TrustingRouter:
                world.contracts[alias] = TrustingRouter(alias, pool_balance=params.get("pool_balance", 50.0))
            elif cls is LegitimateComputer:
                world.contracts[alias] = LegitimateComputer(alias, cap=params.get("cap", 1.0))
            elif cls is SelfLiquidationMarket:
                world.contracts[alias] = SelfLiquidationMarket(
                    alias, liquidation_bonus_bps=params.get("liquidation_bonus_bps", 1500.0),
                )
            elif cls is UncheckedBalanceToken:
                world.contracts[alias] = UncheckedBalanceToken(alias, checked=params.get("checked", False))
            elif cls is MockFlashLender:
                world.contracts[alias] = MockFlashLender(alias, fee_bps=params.get("fee_bps", 0.0))
            elif cls is FlashLoanReentrantAttacker:
                pending_refs[alias] = ("flashloan_reentrant_attacker", params)
            elif cls is AccessControlTarget:
                world.contracts[alias] = AccessControlTarget(
                    alias,
                    owner=params.get("owner", "deployer"),
                    enforce_check=params.get("enforce_check", False),
                )
            else:
                world.contracts[alias] = cls(alias)

        for alias, (kind, params) in pending_refs.items():
            if kind == "market":
                pool_alias = params["pool_alias"]
                world.contracts[alias] = OracleFedLendingMarket(
                    alias, pool=world.contracts[pool_alias],
                    reserve_eth=params.get("reserve_eth", 50.0),
                )
            elif kind == "oracle_attacker":
                world.contracts[alias] = OracleManipulationAttacker(
                    alias, pool_alias=params["pool_alias"], market_alias=params["market_alias"],
                )
            elif kind == "sig_replayer":
                world.contracts[alias] = SignatureReplayer(
                    alias, target_alias=params["target_alias"], times=params.get("times", 3),
                )
            elif kind == "share_inflation_attacker":
                world.contracts[alias] = ShareInflationAttacker(alias, vault_alias=params["vault_alias"])
            elif kind == "flashloan_reentrant_attacker":
                world.contracts[alias] = FlashLoanReentrantAttacker(
                    alias, lender_alias=params["lender_alias"], vault_alias=params["vault_alias"],
                    max_reentries=scenario.attacker_max_reentries,
                )

        ledger.balances["attacker"] = scenario.attacker.initial_eth
        for alias, bal in scenario.initial_state.balances.items():
            ledger.balances[alias] = bal

        for alias, contract in world.contracts.items():
            if isinstance(contract, SimplePool):
                ledger.balances.setdefault(alias, contract.reserve_a)
                world.token_b_ledger.balances[alias] = contract.reserve_b

        before = {a: ledger.get(a) for a in list(world.contracts) + ["attacker"]}

        reverted, revert_reason = False, None
        for step in scenario.initial_state.custom_setup_calls + scenario.steps:
            # Copy contracts together so a market keeps its reference to the restored pool.
            snapshot = deepcopy((world.ledger, world.token_b_ledger, world.contracts))
            trace_length = len(world.call_trace)
            try:
                self._dispatch(step, world)
            except MockRevert as e:
                world.ledger, world.token_b_ledger, world.contracts = snapshot
                del world.call_trace[trace_length:]
                if not step.expected_revert:
                    reverted, revert_reason = True, e.reason
                    break

        after = {a: world.ledger.get(a) for a in list(world.contracts) + ["attacker"]}

        state_vars = {}
        for alias in set(list(before.keys()) + list(after.keys())):
            state_vars[alias] = {
                "eth_balance_before": before.get(alias, 0.0),
                "eth_balance_after": after.get(alias, 0.0),
            }
        # convenience alias for the verifier's "legitimate_entitlement"
        if "attacker" in state_vars:
            state_vars["attacker"]["legitimate_entitlement"] = scenario.attacker.initial_eth

        # generic extension point: any mock contract exposing state_vars()
        # gets those merged in under its own alias, so success_conditions
        # can reference e.g. `vault.owner` or `vault.last_caller` via
        # safe_eval exactly like the ETH-balance fields above — this is
        # what lets AccessControlTarget / InitializableTarget scenarios
        # be verified without ad hoc inspection of call_trace.
        for alias, contract in world.contracts.items():
            if hasattr(contract, "state_vars"):
                state_vars.setdefault(alias, {}).update(contract.state_vars())

        return ExecutionResult(
            scenario_id=scenario.scenario_id,
            reverted=reverted,
            revert_reason=revert_reason,
            state_vars=state_vars,
            state_diff={"before": before, "after": after},
            call_trace=world.call_trace,
            engine="mock",
        )

    def _dispatch(self, step, world: MockWorld):
        target = world.contracts.get(step.target)
        fn_name = step.function.split("(")[0]
        caller = "attacker" if step.caller == "attacker" else step.caller
        if target is None:
            raise MockRevert(f"unknown call target: {step.target}")
        method = getattr(target, fn_name, None)
        if method is None:
            raise MockRevert(f"{step.target} has no mock method {fn_name}()")

        # step.args (positional, matching the real Solidity signature) are
        # mapped onto whatever extra keyword params this mock method
        # declares beyond (caller, world, msg_value) — e.g. signature_id,
        # donation_amount. Lets scenario YAML/steps pass "args: [sig-1]"
        # without every mock method needing bespoke dispatch handling.
        extra_kwargs = {}
        if step.args:
            import inspect
            params = list(inspect.signature(method).parameters.keys())
            extra_names = [p for p in params if p not in ("self", "caller", "world", "msg_value")]
            extra_kwargs = dict(zip(extra_names, step.args))

        method(caller, world, msg_value=step.value_eth, **extra_kwargs)
