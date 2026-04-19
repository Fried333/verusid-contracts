# Verus Deterministic Contract Standard (VCS)
## Extending VerusID Content Multimap from Passive to Active

### The Idea

VerusID's `contentMultiMap` already stores arbitrary VDXF key-value data on every identity. Right now it's **passive** — off-chain systems read it and act on it (subscription terms, profile data, credentials). The extension is making the protocol itself **read and act on specific VDXF keys** during transaction processing.

Two existing functions become contentMultiMap-aware:

1. **`serverchecker.cpp`** — spending authorization. Already checks if an identity is locked, revoked, multisig. Extended to also check policy VDXF keys (whitelist).

2. **`AddReserveTransferImportOutputs`** — transfer processing. Already handles conversions, refunds, identity exports. Extended to also check contract VDXF keys (splitter, escrow, lending).

No new eval codes. No new transaction types. No new subsystems. Just two existing functions looking at one more field they already have access to.

### What Verus Already Provides

Everything below builds on existing protocol features:

| Feature | Already In Protocol | Used By |
|---|---|---|
| Identity locking | `FLAG_LOCKED`, `unlockAfter` | Policies — locked IDs can only stake/self-send |
| Staking from locked IDs | `serverchecker.cpp` line 169: `isStake` bypasses lock | Staking pools |
| Self-send from locked IDs | `serverchecker.cpp` line 170: `sourceIsSelf` | Policies extend this with whitelist |
| Multisig | `minSigs` + multiple primary addresses | Parameter protection — no special immutability needed |
| Revocation / Recovery | `revocationAuthority`, `recoveryAuthority` | Contract admin, emergency override |
| Timelocks | `unlockAfter`, `nLockTime` | Dead man's switch, time-delayed operations |
| Content multimap | `std::multimap<uint160, std::vector<unsigned char>>` | Contract params, policy whitelists, state |
| VDXF keys | `CVDXF::GetDataKey()` — deterministic uint160 from names | Contract types, actions, policy keys |
| Reserve transfers | `CReserveTransfer` + `AddReserveTransferImportOutputs` | Contract actions — existing pipeline |
| gatewayCode | `CTransferDestination.gatewayCode` — uint160 | Action dispatch — "code for function to execute on gateway" |
| Basket conversion prices | `CCoinbaseCurrencyState.conversionPrice[]` | On-chain oracle for lending — no Chainlink needed |
| Pre-signed TXs + nLockTime | Subscription protocol (tested mainnet 2026-03-27) | Proved the pattern works on existing infra |

### Why Pre-Signing Isn't Enough

The [VerusSub protocol](../Ideas/VerusSub-Protocol.md) proved that subscriptions work today using pre-signed nLockTime transactions stored on contentMultiMap. But pre-signing is a workaround with hard limits:

- Must know all amounts upfront (can't handle variable pricing or interest)
- Must lock up all funds upfront (12 months of payments day one)
- Needs an off-chain broadcaster
- Can't react to on-chain state (can't split based on what arrives, can't liquidate based on price)
- Can't restrict future unknown operations (policy whitelists)

Making contentMultiMap active at the protocol level solves all of these.

---

## Part 1: Policy Layer — serverchecker.cpp

### The Attack Vector

A locked VerusID can already stake (self-send). If we extend this to allow self-send conversions (for arb bots, market makers), there's a value extraction attack:

1. Attacker compromises keys of a locked identity holding 10,000 VRSC
2. Attacker creates `ScamBasket` — full of worthless tokens they control
3. Converts 10,000 VRSC → ScamBasket tokens (returns to same address — self-send passes)
4. Real VRSC flows into basket reserves, attacker withdraws
5. Locked identity holds worthless tokens — value drained without funds "leaving"

### The Fix: Whitelist Policy

VDXF keys on the identity's contentMultiMap:

```
vrsc::contract.policy.allowedbaskets    = [uint160]  // whitelisted basket currency IDs
vrsc::contract.policy.allowedcurrencies = [uint160]  // whitelisted currency IDs
```

**Rule:**
- No policy keys → locked identity can only stake (backward compatible, nothing changes)
- Policy keys present → locked identity can also self-send, but ONLY through whitelisted baskets/currencies
- No whitelist = no self-sends beyond staking. Protection is mandatory.

### Code Change

**File: `src/script/serverchecker.cpp`** — line ~168, extend the existing spending authorization:

```cpp
// CURRENT:
if (id.IsValidUnrevoked() &&
    ((isStake && (!enforceIDStakeHeightLimit || ...)) ||
     sourceIsSelf ||
     !id.IsLocked(spendHeight)))

// EXTENDED:
if (id.IsValidUnrevoked() &&
    ((isStake && (!enforceIDStakeHeightLimit || ...)) ||
     sourceIsSelf ||
     (id.IsLocked(spendHeight) && IsSelfSend(tx, id) && CheckPolicyWhitelist(id, tx)) ||
     !id.IsLocked(spendHeight)))
```

`CheckPolicyWhitelist` reads `vrsc::contract.policy.allowedbaskets` from the identity's contentMultiMap and validates that every conversion in the transaction targets a whitelisted basket. ~40 lines.

### Use Cases

```bash
# Arb bot — locked, can only trade through Bridge.vETH
verus updateidentity '{"name":"arb-bot@",
  "flags": 1,
  "contentmultimap": {
    "vrsc::contract.policy.allowedbaskets": ["Bridge.vETH"],
    "vrsc::contract.policy.allowedcurrencies": ["VRSC","vETH","DAI"]
  }}'
# Keys stolen? Attacker can only arb through Bridge.vETH. Can't drain.

# Treasury — locked, can only hold approved stablecoins
verus updateidentity '{"name":"treasury@",
  "flags": 1,
  "contentmultimap": {
    "vrsc::contract.policy.allowedbaskets": ["Bridge.vETH"],
    "vrsc::contract.policy.allowedcurrencies": ["DAI","VRSC"]
  }}'
```

---

## Part 2: Contract Layer — AddReserveTransferImportOutputs

### How It Works

When `AddReserveTransferImportOutputs` processes a reserve transfer whose destination is an identity with `vrsc::contract.type` in its contentMultiMap, it dispatches to template-specific logic instead of creating a normal output. The action is specified via `CTransferDestination.gatewayCode` — an existing uint160 field for "code for function to execute on the gateway." The contract identity IS the gateway.

### Contract Types

Contract type is stored as a uint160 VDXF key hash in the identity's contentMultiMap:

```
vrsc::contract.type = VDXF_KEY("vrsc::contract.template.splitter")   // or escrow, lending, etc.
```

The import processor reads this key, matches against known template hashes, and dispatches.

### Access Control

Contract parameter protection uses VerusID's existing access control — no special immutability layer:

- **Immutable params:** Lock identity + revocation to cold key
- **Changeable with consent:** Multisig — all parties must agree to update
- **Admin-controlled:** Single owner retains update rights
- **Emergency:** Recovery authority can always override

### Contract State

Stateful contracts (escrow, lending) store state in separate UTXOs at the contract identity's address, containing VDXF structured data with `vrsc::contract.state` keys. Each state transition spends the old state UTXO and creates a new one — same pattern as notarizations.

### Transfers Must Use sendcurrency

Contract logic executes during import processing. Direct sends (`sendtoaddress`) bypass the import pipeline. All contract interactions must use `sendcurrency` (reserve transfers). The spending restriction on contract identities (only via import processing or recovery) ensures direct-sent funds can only be recovered, not spent normally.

---

## Part 3: Templates

### 3.1 Splitter

Auto-distribute incoming funds to multiple recipients by share.

```
vrsc::contract.type                    = VDXF_KEY("vrsc::contract.template.splitter")
vrsc::contract.splitter.recipients     = [{destination, shareBasisPoints}, ...]
vrsc::contract.splitter.minpayout      = int64 (minimum before split triggers)
```

**Stateless** — no state UTXO needed. Import processor creates split outputs directly.

**Precheck:** Shares must sum to 10000 (100%). At least 2 recipients.

### 3.2 Escrow

Hold funds until release conditions are met.

```
vrsc::contract.type                    = VDXF_KEY("vrsc::contract.template.escrow")
vrsc::contract.escrow.parties          = {buyer, seller, arbiter}
vrsc::contract.escrow.amount           = int64
vrsc::contract.escrow.currency         = uint160
vrsc::contract.escrow.timeout          = uint32 (block height — auto-refund)
```

**Actions** (via gatewayCode):
- `vrsc::contract.action.escrow.release` — buyer signs, funds go to seller
- `vrsc::contract.action.escrow.dispute` — either party signs, escalates to arbiter
- `vrsc::contract.action.escrow.arbitrate` — arbiter signs, funds go to winner
- Timeout: block height reached → auto-refund to buyer

**State:** `vrsc::contract.state.escrow.status` = created / funded / released / refunded / disputed

### 3.3 Vesting

Time-locked fund release on a schedule.

```
vrsc::contract.type                    = VDXF_KEY("vrsc::contract.template.vesting")
vrsc::contract.vesting.beneficiary     = CTransferDestination
vrsc::contract.vesting.schedule        = {amount, start, cliff, end, interval}
```

**Action:** `vrsc::contract.action.vesting.claim` — beneficiary signs, receives vested amount.

**State:** `vrsc::contract.state.vesting.claimed` = amount claimed so far.

**Math:** `claimable = total * (currentHeight - start) / (end - start) - claimed`

### 3.4 Subscription

Recurring authorized pulls by a provider.

```
vrsc::contract.type                    = VDXF_KEY("vrsc::contract.template.subscription")
vrsc::contract.subscription.provider   = CTransferDestination
vrsc::contract.subscription.amount     = int64 (per period)
vrsc::contract.subscription.currency   = uint160
vrsc::contract.subscription.period     = uint32 (blocks per billing cycle)
```

**Actions:**
- `vrsc::contract.action.subscription.pull` — provider signs, receives one period's payment. Precheck rejects if period hasn't elapsed.
- `vrsc::contract.action.subscription.cancel` — owner signs, remaining funds returned, state set inactive.

**State:** `vrsc::contract.state.subscription.lastpaid`, `active`

**Note:** The pre-signed nLockTime approach (VerusSub) already works for subscriptions today. The protocol-level version eliminates the need to pre-lock all funds and removes the off-chain broadcaster.

### 3.5 Conditional (Oracle-Triggered)

Release funds based on oracle attestation.

```
vrsc::contract.type                    = VDXF_KEY("vrsc::contract.template.conditional")
vrsc::contract.conditional.oracle      = uint160 (oracle identity)
vrsc::contract.conditional.attestkey   = uint160 (VDXF key oracle must attest to)
vrsc::contract.conditional.recipient   = CTransferDestination
vrsc::contract.conditional.fallback    = CTransferDestination
vrsc::contract.conditional.timeout     = uint32 (block height)
```

Oracle updates its own contentMultiMap with the attestation key → import detects, releases to recipient. Timeout → fallback.

### 3.6 Lending Pool

Collateralized lending using basket conversion prices as on-chain oracle.

```
vrsc::contract.type                    = VDXF_KEY("vrsc::contract.template.lending")
vrsc::contract.lending.collateral      = [uint160]  // accepted collateral currencies
vrsc::contract.lending.borrow          = [uint160]  // lendable currencies
vrsc::contract.lending.pricefeed       = uint160    // basket whose conversionPrice[] is the oracle
vrsc::contract.lending.ltv             = uint32     // max loan-to-value (basis points)
vrsc::contract.lending.liquidation     = uint32     // liquidation threshold (basis points)
vrsc::contract.lending.liquidationbonus = uint32    // liquidator bonus (basis points)
vrsc::contract.lending.interestmodel   = {baseRate, slope1, slope2, kink}
```

**Actions:**
- `vrsc::contract.action.lending.deposit` — lender adds funds to pool
- `vrsc::contract.action.lending.borrow` — borrower posts collateral, receives loan
- `vrsc::contract.action.lending.repay` — borrower repays debt + interest, gets collateral back
- `vrsc::contract.action.lending.withdraw` — lender removes funds (if liquidity available)
- `vrsc::contract.action.lending.liquidate` — anyone liquidates undercollateralized position

**Why basket prices work as oracle:** Verus basket currencies maintain `conversionPrice[]` in `CCoinbaseCurrencyState`, updated every block by actual reserve conversions. These prices are consensus-level, manipulation-resistant (moving them requires depositing/withdrawing real reserves — no flash loans on UTXO), always available, and already used for reserve-to-reserve swaps. No external oracle infrastructure needed.

**Already proven:** The [Verus Oracle](https://github.com/Fried333/verus-oracle) on [scan.verus.cx](https://scan.verus.cx) uses this exact approach — reads `priceinreserve` from basket reserves (`CCoinbaseCurrencyState`), applies depth-weighted averaging across 29 active baskets, and prices 17 currencies with ~0.3% error vs market. No Chainlink, no external oracle nodes, no off-chain price feeds. The oracle worker just reads what the protocol already knows. The lending template would do the same thing but inside `AddReserveTransferImportOutputs` instead of in an off-chain service — same data source, protocol-level consumer instead of API-level.

**Interest math:** Uses `cpp_dec_float_50` (same as existing `CalculateFractionalOut()`) for compound interest with large block gaps. Two-slope model: `rate = baseRate + utilization * slope1` below kink, steeper `slope2` above kink.

---

## Part 4: What Already Works Without Protocol Changes

These are proven today or achievable using existing primitives:

| Use Case | How |
|---|---|
| **Tokens** | `definecurrency` |
| **DEX / AMM** | Basket currencies |
| **Stablecoins** | Reserve-backed baskets |
| **Bridges** | PBaaS + Ethereum bridge |
| **Multisig** | VerusID `minSigs` |
| **Fundraising** | Preconversions |
| **Governance** | `EVAL_VOTING_*` |
| **Dead man's switch** | VerusID timelock |
| **Rate limiting** | VerusID timelock + spending conditions |
| **Time-delayed vault** | VerusID timelock + revocation |
| **Subscriptions (basic)** | Pre-signed nLockTime TXs + contentMultiMap ([tested on mainnet](../Ideas/VerusSub-Protocol.md)) |
| **Vesting (basic)** | Same pattern — N UTXOs with increasing nLockTimes |
| **Escrow (basic)** | 2-of-3 multisig VerusID + nLockTime timeout |

---

## Part 5: Composability — Chained Identities

Each contract identity does one thing. Complex financial flows are built by chaining destinations — the output of contract A becomes the input of contract B, processed in the next import cycle. No recursive dispatch, no reentrancy risk. Same confirm-then-process model that reserve transfers already use.

### Examples

**Royalty Distribution:**
```
Sale revenue
  → royalty-split@ (splitter: 70% artist, 20% label, 10% producer)
    → artist-vest@ (vesting: monthly over 12 months)
    → label-treasury@ (policy: locked, whitelisted baskets only)
```

**Company Payroll:**
```
Company revenue
  → company-split@ (splitter: 60% operations, 30% payroll, 10% reserve)
    → payroll-split@ (splitter: employee shares)
      → employee1-vest@ (vesting: cliff + monthly)
      → employee2-vest@ (vesting: cliff + monthly)
```

**Crowdfund → Milestone → Distribute:**
```
Contributors fund
  → crowdfund@ (conditional: oracle attests "goal met" or timeout refund)
    → project-escrow@ (escrow: milestone-based release)
      → team-split@ (splitter: founder 40%, dev 35%, design 25%)
```

**Subscription → Revenue Share:**
```
Users subscribe
  → service-sub@ (subscription: monthly pull)
    → revenue-split@ (splitter: 40% founder, 30% dev, 30% marketing)
      → dev-vest@ (vesting: 4-year schedule with 1-year cliff)
```

**Lending with Fee Distribution:**
```
Borrower gets liquidated
  → lending-pool@ (lending: liquidation triggers)
    → liquidation-split@ (splitter: 90% repay lenders, 5% liquidator, 5% protocol)
      → protocol-treasury@ (policy: locked, whitelisted)
```

**Protected Market Making:**
```
mm-bot@ (policy: locked, whitelist = Bridge.vETH)
  profits accumulate, periodically swept to
    → profit-split@ (splitter: 80% LPs, 20% operator)
```

**Real Estate Closing:**
```
Buyer deposits
  → property-escrow@ (escrow: awaiting title verification)
    → title-oracle@ attests "clear title"
      → closing-split@ (splitter: seller 94%, agent 3%, taxes 3%)
```

### How Chaining Could Work

The codebase already has the building blocks for multi-step routing. `CReserveTransfer` supports `HasNextLeg()` — a transfer can specify a `gatewayID` and `gatewayCode` on its destination, and the import processor routes it to the next system. There's even a `DEST_NESTEDTRANSFER` type defined for arbitrary chaining, though it's currently stubbed out (`"Nested currency transfers not yet supported"` — reserves.cpp line 3657).

**Possible approaches:**

1. **Implement `DEST_NESTEDTRANSFER`** — The placeholder already exists. A contract template's output could embed a nested reserve transfer targeting the next contract identity. The import processor would create it as an output, and the export → import cycle processes it next block.

2. **Contract outputs as reserve transfers** — When a contract template creates an output to a VerusID that is itself a contract (has `vrsc::contract.type`), it automatically creates a reserve transfer instead of a direct UTXO. This uses the existing export → import pipeline — no new mechanism, just recognizing the destination.

3. **Manual triggering** — Contract A outputs funds to contract B's address. Someone sends a `sendcurrency` action to contract B to trigger processing. Not automatic, requires an external actor, but simple and safe.

4. **Use `gatewayCode` for routing** — The contract template sets `gatewayID = next_contract_identity` and `gatewayCode = action_to_invoke` on its output. The existing next-leg routing handles the rest. This is closest to how cross-chain routing already works.

**The right approach needs dev input** — it depends on whether contract chaining should reuse the cross-chain routing mechanism (option 4), implement the already-planned nested transfers (option 1), or stay simple with manual triggering (option 3).

### Security Advantage Over Ethereum

Regardless of which chaining approach is chosen, the security model is fundamentally different from Ethereum:

- **Each step is a separate identity** with its own multisig, revocation, and recovery
- **If one step has a bug**, revoke that identity — the others keep running
- **No reentrancy** — each step processes in a separate block, never recursively in the same transaction
- **Each identity is auditable independently** — simpler to verify one-purpose contracts
- **Composability is additive** — adding a new step doesn't increase attack surface of existing steps

A single identity can also combine policy + contract keys on the same contentMultiMap (e.g., a locked lending pool with a basket whitelist). But for multi-step flows, chaining separate identities is cleaner and more secure.

---

## Part 6: What's Left Out (By Design)

| What | Why It's Excluded |
|---|---|
| **Contract-to-contract calls** | Reentrancy attacks. Chained identities achieve composability safely via sequential block processing. |
| **Flash loans** | Account-model trick, impossible on UTXO. The mechanism that enables most DeFi exploits. |
| **Arbitrary computation** | Turing completeness creates unbounded attack surface. Templates are auditable, bounded, and predictable. |
| **Novel unanticipated primitives** | Requires adding a new template handler. Trade-off: can't deploy arbitrary logic, but every deployed template is protocol-verified. |

These are the categories responsible for the majority of smart contract exploits. Their absence is the security model, not a limitation.

---

## Part 7: Code Change Summary

| File | Change | Lines (est.) |
|---|---|---|
| `script/serverchecker.cpp` | Policy whitelist check in spending authorization | 50 |
| `pbaas/vdxf.h` | VDXF key constants for policies, contracts, actions | 300 |
| **`pbaas/contracts.h`** (new) | Contract/policy structs, serialization | 500 |
| **`pbaas/contracts.cpp`** (new) | Template logic (split, escrow, vest, lend, etc.) | 1000 |
| `pbaas/reserves.cpp` | Contract dispatch in `AddReserveTransferImportOutputs` | 150 |
| `pbaas/pbaas.cpp` | Contract-aware check in `PrecheckReserveTransfer` | 60 |
| `pbaas/pbaas.h` | Activation timestamp | 5 |
| `pbaas/identity.cpp` | Contract identity spending restriction | 40 |
| `rpc/pbaasrpc.cpp` | RPC commands (createcontract, getcontract, contractaction) | 200 |
| **Total** | | **~2300** |

No changes to `cc/eval.h`, `cc/CCcustom.cpp`, or `cc/CCaddresses.cpp`. Everything operates through VDXF keys within existing smart transaction infrastructure.

---

## Part 8: Rollout

### Phase 1: Policy Whitelist
- Smallest change (~50 lines in serverchecker.cpp)
- Immediately useful — arb bots, treasuries, market makers
- Security feature, not new functionality
- Low risk — only affects locked identities with policy keys

### Phase 2: Splitter
- Simplest contract template, stateless
- Validates the full pipeline: identity creation → contract detection → import dispatch → split outputs
- ~300 lines in contracts.cpp + reserves.cpp integration

### Phase 3: Escrow + Vesting + Subscription
- Introduces stateful contracts (state UTXOs)
- Introduces the action mechanism (gatewayCode dispatch)
- ~500 lines additional

### Phase 4: Lending
- Most complex — multi-position state, interest accrual, liquidation
- Uses basket conversion prices as oracle
- ~600 lines additional
- Heavy testnet validation required
