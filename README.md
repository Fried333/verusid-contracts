# Verus Deterministic Contract Standard (VCS)
## Policies and Contracts for VerusID via Content Multimap

### Overview

This spec defines two layers of programmable behavior for VerusIDs, both implemented through VDXF keys in the `contentMultiMap` — no virtual machine, no bytecode, no Turing completeness:

**Layer 1: Policies** — Restrictions on what a locked identity can do. Security-focused. Protects funds from key compromise by whitelisting allowed operations. Built on the existing capability where locked VerusIDs can stake (self-send).

**Layer 2: Contracts** — Rules about how funds are managed. Functional. Works on any identity (locked or unlocked). Enables subscriptions, escrow, revenue splits, lending.

| Layer | Identity State | Purpose | Example |
|-------|---------------|---------|---------|
| **Policy** | Locked | Restrict what the owner can do | Arb bot, market maker, treasury |
| **Contract** | Locked (usually) | Define what happens to funds | Escrow, splitter, vesting, lending |
| **Contract** | Unlocked (optional) | Owner-controlled fund rules | Subscription (owner commits voluntarily) |

Most contracts need locking to be trustless — without it, the owner can bypass the rules and spend directly.

Parameter protection (preventing changes to splitter shares, escrow terms, etc.) is handled by VerusID's existing access control — no special immutability check needed:

- **Immutable params:** Lock identity + revocation authority set to cold key
- **Changeable with consent:** Multisig — all parties must agree to update
- **Admin-controlled:** Single owner retains update rights

VerusID already has locking, multisig (`minSigs` + multiple primary addresses), revocation, and recovery. The contract system doesn't need to reinvent access control — the identity IS the access control layer. Subscriptions are the exception: the owner voluntarily authorizes pulls from their own funds and can cancel anytime.

### Why Two Layers

A locked VerusID can already stake — the staking spend goes to itself and the balance grows. The protocol allows this in `serverchecker.cpp`:

```cpp
if (id.IsValidUnrevoked() &&
    ((isStake && ...) ||     // staking: ALLOWED even when locked
     sourceIsSelf ||          // internal operations
     !id.IsLocked(spendHeight)))  // everything else: only if NOT locked
```

**Layer 1 (Policies)** extends this: a locked identity with a `vrsc::contract.policy.allowedbaskets` whitelist in its multimap can ALSO do self-sends (conversions), but ONLY through whitelisted baskets. Without a whitelist, locked = staking only (backward compatible). This is a security feature — it enables arb/DeFi from locked identities while preventing value extraction through malicious baskets.

**Layer 2 (Contracts)** is independent: a VerusID with `vrsc::contract.type` in its multimap has rules about how incoming/outgoing funds are handled. These rules execute during `AddReserveTransferImportOutputs`. The identity can be locked or unlocked — a subscription doesn't need locking, but a lending pool does.

---

## Part 1: Policy Layer — Secure Self-Send for Locked Identities

### 1.0 The Attack Vector Policies Prevent

Without a whitelist, allowing self-sends from locked identities creates a value extraction attack:

1. Attacker compromises keys of a locked identity holding 10,000 VRSC
2. Attacker creates `ScamBasket` — a basket full of worthless tokens they control
3. Attacker converts 10,000 VRSC → ScamBasket tokens (returns to same address, self-send passes)
4. Real VRSC flows into the basket's reserves, attacker withdraws it
5. Locked identity now holds worthless ScamBasket tokens — value drained without funds "leaving"

**The whitelist prevents this.** A locked identity with `allowedbaskets = [Bridge.vETH]` can only convert through Bridge.vETH. The attacker can't route through a scam basket. Worst case: attacker makes bad trades on Bridge.vETH, losing on spread — not losing principal.

### 1.1 Policy VDXF Keys

```
vrsc::contract.policy.allowedbaskets    = [uint160]  // basket currency IDs allowed for conversions
vrsc::contract.policy.allowedcurrencies = [uint160]  // currency IDs allowed in any operation
```

If no policy keys are present → locked identity can only stake (backward compatible).
If policy keys are present → locked identity can also self-send through whitelisted operations.

### 1.2 Code Change — serverchecker.cpp

**File: `src/script/serverchecker.cpp`** — line ~168, extend the spending authorization:

```cpp
if (id.IsValidUnrevoked() &&
    ((isStake && (!enforceIDStakeHeightLimit || (idHeight && (spendHeight - idHeight) >= VERUS_MIN_STAKEAGE))) ||
     sourceIsSelf ||
     (id.IsLocked(spendHeight) && isSelfSend && CheckPolicyWhitelist(id, tx, spendHeight)) ||  // NEW
     !id.IsLocked(spendHeight)))
{
```

Where `isSelfSend` checks that ALL outputs in the transaction go back to the same identity address, and `CheckPolicyWhitelist` validates:

```cpp
bool CheckPolicyWhitelist(const CIdentity &id, const CTransaction &tx, uint32_t height)
{
    // Read allowed baskets from contentMultiMap
    uint160 basketPolicyKey = CVDXF::GetDataKey("vrsc::contract.policy.allowedbaskets", ...);
    auto it = id.contentMultiMap.find(basketPolicyKey);
    if (it == id.contentMultiMap.end())
        return false;  // no policy = no self-sends (only staking)

    std::set<uint160> allowedBaskets;
    // deserialize the whitelist from multimap value
    // ...

    // Check every reserve transfer in the transaction
    for (auto &vout : tx.vout)
    {
        COptCCParams p;
        CReserveTransfer rt;
        if (vout.scriptPubKey.IsPayToCryptoCondition(p) &&
            p.evalCode == EVAL_RESERVE_TRANSFER &&
            (rt = CReserveTransfer(p.vData[0])).IsValid())
        {
            // The via currency (basket) must be on the whitelist
            uint160 importCurrency = rt.IsImportToSource() ? rt.FirstCurrency() : rt.destCurrencyID;
            if (!allowedBaskets.count(importCurrency))
                return false;

            // If allowedcurrencies policy exists, check currency whitelist too
            // ...
        }
    }
    return true;
}
```

### 1.3 Use Cases

**Arb Bot:**
```bash
# Lock identity, set whitelist
verus updateidentity '{"name":"my-arb-bot@", "flags": 1,
  "contentmultimap": {
    "vrsc::contract.policy.allowedbaskets": ["Bridge.vETH"],
    "vrsc::contract.policy.allowedcurrencies": ["VRSC", "vETH", "DAI"]
  }}'

# Bot runs, converts VRSC↔vETH↔DAI through Bridge — all self-sends
# Keys compromised? Attacker can only arb through Bridge.vETH
# Recover identity, lock attacker out
```

**Treasury:**
```bash
# Organization funds locked, can only convert between stablecoins
verus updateidentity '{"name":"treasury@", "flags": 1,
  "contentmultimap": {
    "vrsc::contract.policy.allowedbaskets": ["Bridge.vETH"],
    "vrsc::contract.policy.allowedcurrencies": ["DAI", "USDC", "VRSC"]
  }}'
```

**Market Maker:**
```bash
# Locked identity provides liquidity, restricted to specific basket
verus updateidentity '{"name":"mm-bot@", "flags": 1,
  "contentmultimap": {
    "vrsc::contract.policy.allowedbaskets": ["Bridge.vETH", "Kaiju"]
  }}'
```

---

## Part 2: Contract Layer — Fund Management Rules

### 2.0 Architecture: VDXF-Based, Not Eval-Based

> **Important:** Contracts do NOT use a new eval code. Eval codes (`EVAL_RESERVE_TRANSFER`, `EVAL_IDENTITY_PRIMARY`, etc.) are deep protocol primitives — the wrong layer for contracts. Contracts are a higher-level concept built ON existing smart transaction types using VDXF keys.

A contract identity is a VerusID whose `contentMultiMap` contains a `vrsc::contract.type` VDXF key. Contract actions are submitted as reserve transfers with the action specified via `CTransferDestination.gatewayCode` (a uint160 field that already exists for "code for function to execute on the gateway"). The contract identity IS the gateway; the `gatewayCode` is the VDXF key of the action.

**What this means for the code:**
- No new entry in `src/cc/eval.h`
- No new registration in `src/cc/CCcustom.cpp`
- No new address/pubkey/WIF triplet
- Contract dispatch is added to the EXISTING precheck and import processing paths
- Contract types and actions are defined entirely as VDXF keys

> **Note on source naming:** The source code still uses legacy Komodo naming (`cc/`, `CCcustom.cpp`, `COptCCParams`, etc.) from the crypto-conditions era. Verus Smart Transactions are architecturally different — they use a verified precheck system that goes far beyond form validation, rejecting anything clearly recognizable as unable to succeed. File paths below reflect the current source layout, not the architecture.

### 1.2 New Contract Data Structure

**New file: `src/pbaas/contracts.h`**

```cpp
#include "identity.h"
#include "reserves.h"
#include "vdxf.h"

// Contract template identifiers — stored as uint160 VDXF key hashes in contentMultiMap.
// The on-chain value of vrsc::contract.type is a uint160 (the VDXF key hash of the template),
// NOT an integer enum. The enum below is for internal dispatch only.
class CVerusContract
{
public:
    enum EContractType
    {
        CONTRACT_INVALID = 0,
        CONTRACT_SPLITTER = 1,
        CONTRACT_ESCROW = 2,
        CONTRACT_VESTING = 3,
        CONTRACT_SUBSCRIPTION = 4,
        CONTRACT_CONDITIONAL = 5,
        CONTRACT_LENDING = 6,
    };

    // VDXF key names — the on-chain contract type value is the uint160 hash of these
    static std::string ContractTypeKeyName()        { return "vrsc::contract.type"; }
    static std::string ContractVersionKeyName()     { return "vrsc::contract.version"; }

    // Template VDXF key names — stored as uint160 hashes in the multimap
    static std::string SplitterTemplateName()       { return "vrsc::contract.template.splitter"; }
    static std::string EscrowTemplateName()         { return "vrsc::contract.template.escrow"; }
    static std::string VestingTemplateName()        { return "vrsc::contract.template.vesting"; }
    static std::string SubscriptionTemplateName()   { return "vrsc::contract.template.subscription"; }
    static std::string ConditionalTemplateName()    { return "vrsc::contract.template.conditional"; }
    static std::string LendingTemplateName()        { return "vrsc::contract.template.lending"; }

    // Read contract type from an identity's contentMultiMap
    // Reads the uint160 value stored at vrsc::contract.type key,
    // matches it against known template VDXF key hashes,
    // returns the internal enum for dispatch
    static EContractType GetContractType(const CIdentity &identity);

    // Check if an identity is a contract
    static bool IsContract(const CIdentity &identity)
    {
        return GetContractType(identity) != CONTRACT_INVALID;
    }

    static uint160 ContractTypeKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ContractTypeKeyName(), nameSpace);
        return key;
    }

    static uint160 ContractVersionKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(ContractVersionKeyName(), nameSpace);
        return key;
    }

    // Template key lookups — for matching against the stored type value
    static uint160 SplitterTemplateKey()
    {
        static uint160 nameSpace;
        static uint160 key = CVDXF::GetDataKey(SplitterTemplateName(), nameSpace);
        return key;
    }
    // ... same pattern for each template
};

// ============================================================
// Splitter Contract
// ============================================================
class CContractSplitter
{
public:
    struct Recipient
    {
        CTransferDestination destination;
        uint64_t shareBasisPoints;  // 10000 = 100%
        uint160 currencyFilter;     // null = all currencies

        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(destination);
            READWRITE(VARINT(shareBasisPoints));
            READWRITE(currencyFilter);
        }
    };

    std::vector<Recipient> recipients;
    CAmount minPayout;              // minimum satoshis before split triggers

    static std::string RecipientsKeyName()  { return "vrsc::contract.splitter.recipients"; }
    static std::string MinPayoutKeyName()   { return "vrsc::contract.splitter.minpayout"; }

    // Deserialize from identity contentMultiMap
    static CContractSplitter FromIdentity(const CIdentity &identity);

    // Validate parameters
    bool IsValid() const;

    // Generate split outputs for a given input amount
    // Returns CTxOut vector to add to the import transaction
    std::vector<CTxOut> ProcessDeposit(
        const CCurrencyValueMap &deposited,
        CAmount nativeDeposited) const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(recipients);
        READWRITE(VARINT(minPayout));
    }
};

// ============================================================
// Escrow Contract
// ============================================================
class CContractEscrow
{
public:
    enum EStatus
    {
        STATUS_CREATED = 0,
        STATUS_FUNDED = 1,
        STATUS_RELEASED = 2,
        STATUS_REFUNDED = 3,
        STATUS_DISPUTED = 4,
    };

    enum EAction
    {
        ACTION_DEPOSIT = 1,
        ACTION_RELEASE = 2,
        ACTION_DISPUTE = 3,
        ACTION_ARBITRATE = 4,
    };

    CTransferDestination buyer;
    CTransferDestination seller;
    CTransferDestination arbiter;  // optional
    CAmount amount;
    uint160 currencyID;
    uint32_t timeout;              // block height
    uint8_t requiredSigs;          // 1=buyer-only, 2=buyer+seller

    // State (stored separately — see section 1.5)
    uint8_t status;

    static std::string PartiesKeyName()     { return "vrsc::contract.escrow.parties"; }
    static std::string AmountKeyName()      { return "vrsc::contract.escrow.amount"; }
    static std::string TimeoutKeyName()     { return "vrsc::contract.escrow.timeout"; }
    static std::string StatusKeyName()      { return "vrsc::contract.state.escrow.status"; }
    static std::string ActionReleaseKeyName()   { return "vrsc::contract.action.escrow.release"; }
    static std::string ActionDisputeKeyName()   { return "vrsc::contract.action.escrow.dispute"; }
    static std::string ActionArbitrateKeyName() { return "vrsc::contract.action.escrow.arbitrate"; }

    static CContractEscrow FromIdentity(const CIdentity &identity);
    bool IsValid() const;

    // Process an action, returns outputs and new state
    // actionKey: which action (release/dispute/arbitrate)
    // signerAddress: who signed the action transaction
    // currentHeight: for timeout checks
    struct Result {
        std::vector<CTxOut> outputs;
        uint8_t newStatus;
        bool valid;
        std::string error;
    };
    Result ProcessAction(
        const uint160 &actionKey,
        const CTxDestination &signerAddress,
        uint32_t currentHeight,
        const CCurrencyValueMap &contractBalance) const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(buyer);
        READWRITE(seller);
        READWRITE(arbiter);
        READWRITE(VARINT(amount));
        READWRITE(currencyID);
        READWRITE(VARINT(timeout));
        READWRITE(requiredSigs);
        READWRITE(status);
    }
};

// ============================================================
// Vesting Contract
// ============================================================
class CContractVesting
{
public:
    CTransferDestination beneficiary;
    CAmount totalAmount;
    uint160 currencyID;
    uint32_t startHeight;
    uint32_t cliffHeight;
    uint32_t endHeight;
    uint32_t interval;             // 0 = continuous (per-block)

    // State
    CAmount claimed;

    static std::string BeneficiaryKeyName() { return "vrsc::contract.vesting.beneficiary"; }
    static std::string ScheduleKeyName()    { return "vrsc::contract.vesting.schedule"; }
    static std::string ClaimedKeyName()     { return "vrsc::contract.state.vesting.claimed"; }
    static std::string ActionClaimKeyName() { return "vrsc::contract.action.vesting.claim"; }

    CAmount GetClaimable(uint32_t currentHeight) const;
    static CContractVesting FromIdentity(const CIdentity &identity);
    bool IsValid() const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(beneficiary);
        READWRITE(VARINT(totalAmount));
        READWRITE(currencyID);
        READWRITE(VARINT(startHeight));
        READWRITE(VARINT(cliffHeight));
        READWRITE(VARINT(endHeight));
        READWRITE(VARINT(interval));
        READWRITE(VARINT(claimed));
    }
};
```

### 1.3 VDXF Key Registration

**File: `src/pbaas/vdxf.h`** — Add static key functions following the existing pattern (currently lines 259-786):

```cpp
// Contract keys — added after existing CurrencyStartNotarization block
static std::string ContractTypeKeyName()                { return "vrsc::contract.type"; }
static uint160 ContractTypeKey()
{
    static uint160 nameSpace;
    static uint160 key = GetDataKey(ContractTypeKeyName(), nameSpace);
    return key;
}

static std::string ContractVersionKeyName()             { return "vrsc::contract.version"; }
static std::string ContractSplitterRecipientsKeyName()  { return "vrsc::contract.splitter.recipients"; }
static std::string ContractSplitterMinPayoutKeyName()   { return "vrsc::contract.splitter.minpayout"; }
static std::string ContractEscrowPartiesKeyName()       { return "vrsc::contract.escrow.parties"; }
static std::string ContractEscrowAmountKeyName()        { return "vrsc::contract.escrow.amount"; }
static std::string ContractEscrowTimeoutKeyName()       { return "vrsc::contract.escrow.timeout"; }
static std::string ContractVestingScheduleKeyName()     { return "vrsc::contract.vesting.schedule"; }
// ... etc, each with matching Key() function
```

### 1.4 Contract State — Separate UTXO (Recommended)

Rather than modifying identities from consensus (which would break the identity authorization model), contract state lives in a separate UTXO type, analogous to how `CCoinbaseCurrencyState` lives in notarizations, not in `CCurrencyDefinition`.

**File: `src/pbaas/contracts.h`** — Add:

```cpp
// Contract state UTXO — linked to a contract identity
// Spent and recreated on each state transition (like notarizations)
class CContractState
{
public:
    uint32_t version;
    uint160 contractID;             // the identity ID of the contract
    uint32_t blockHeight;           // height of last state update
    std::map<uint160, std::vector<unsigned char>> stateData;  // VDXF key → serialized state

    enum {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_CURRENT = 1,
    };

    CContractState() : version(VERSION_INVALID), blockHeight(0) {}

    bool IsValid() const { return version >= VERSION_FIRST; }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(version));
        READWRITE(contractID);
        READWRITE(VARINT(blockHeight));
        READWRITE(stateData);
    }
};
```

The state UTXO is held at the contract identity's address under the identity's existing smart transaction type. On each state transition, the import processor spends the old state UTXO and creates a new one with updated values. This is exactly how notarizations work — each new notarization spends the previous one. Contract identity recognition happens via VDXF key lookup, not a dedicated eval code.

### 1.5 Precheck — Extend Existing PrecheckReserveTransfer

**File: `src/pbaas/pbaas.cpp`** — The contract precheck logic is added INSIDE the existing `PrecheckReserveTransfer()` function (line 4894), not as a separate precheck function. When a reserve transfer targets an identity with `vrsc::contract.type` in its multimap, the precheck dispatches to template-specific validation.

**File: `src/pbaas/contracts.cpp`** (new file) — Contains the template-specific precheck functions called from `PrecheckReserveTransfer`:

```cpp
#include "contracts.h"
#include "pbaas.h"

// Called from PrecheckReserveTransfer when destination is a contract identity
bool PrecheckContractTransfer(const CReserveTransfer &rt,
                              const CIdentity &contractIdentity,
                              CValidationState &state, uint32_t height)
{
    if (contractIdentity.IsRevoked())
        return state.Error("Cannot send to revoked contract identity — contract paused");

    CVerusContract::EContractType cType = CVerusContract::GetContractType(contractIdentity);

    // Extract action from gatewayCode — CTransferDestination already has this field
    // for specifying "code for function to execute on the gateway".
    // The contract identity IS the gateway; gatewayCode is the VDXF key of the action.
    uint160 actionKey = rt.destination.gatewayCode;

    switch (cType)
    {
        case CVerusContract::CONTRACT_SPLITTER:
            // Splitter accepts any transfer — no action needed
            return true;

        case CVerusContract::CONTRACT_ESCROW:
        {
            CContractEscrow escrow = CContractEscrow::FromIdentity(contractIdentity);
            if (!escrow.IsValid())
                return state.Error("Invalid escrow contract parameters");

            if (actionKey == CVDXF::GetDataKey(CContractEscrow::ActionReleaseKeyName(), ...))
            {
                if (escrow.status != CContractEscrow::STATUS_FUNDED)
                    return state.Error("Escrow not in funded state — cannot release");
                // Verify signer authorization checked at import time
            }
            else if (actionKey == CVDXF::GetDataKey(CContractEscrow::ActionDisputeKeyName(), ...))
            {
                if (escrow.status != CContractEscrow::STATUS_FUNDED)
                    return state.Error("Escrow not in funded state — cannot dispute");
                if (!escrow.arbiter.IsValid())
                    return state.Error("No arbiter defined for this escrow");
            }
            return true;
        }

        case CVerusContract::CONTRACT_LENDING:
        {
            CContractLending lending = CContractLending::FromIdentity(contractIdentity);
            if (actionKey == CVDXF::GetDataKey(CContractLending::ActionBorrowKeyName(), ...))
            {
                // Reject if collateral currency not in accepted list
                // Reject if borrow currency not in lendable list
            }
            else if (actionKey == CVDXF::GetDataKey(CContractLending::ActionLiquidateKeyName(), ...))
            {
                // Reject if target position is NOT undercollateralized
            }
            return true;
        }

        default:
            return true;  // unknown contract type — allow transfer, import will handle
    }
}
```

### 1.6 Import Processing — Extend AddReserveTransferImportOutputs

**File: `src/pbaas/reserves.cpp`** — Inside `AddReserveTransferImportOutputs()` (the 2200-line function at line 4244), after the existing transfer processing loop, add contract dispatch.

The key insertion point is where transfers are processed into outputs. Currently the function handles:
- Normal transfers (lines ~4500-5100)
- Conversion results (lines ~5700-6000)
- Fee distribution (lines ~6000-6400)

Add a new section after transfers are matched but before outputs are finalized:

```cpp
// ============================================================
// CONTRACT PROCESSING
// After normal transfer matching, check if any transfer
// destinations are contract identities and dispatch
// ============================================================
for (auto &oneTransfer : exportTransfers)
{
    CTransferDestination &dest = oneTransfer.destination;
    if (dest.TypeNoFlags() != CTransferDestination::DEST_ID)
        continue;

    CIdentityID destID(dest.destination);
    CIdentity contractIdentity;
    if (!GetIdentity(destID, contractIdentity, height))
        continue;

    CVerusContract::EContractType cType = CVerusContract::GetContractType(contractIdentity);
    if (cType == CVerusContract::CONTRACT_INVALID)
        continue;  // not a contract, normal transfer

    // This transfer targets a contract — dispatch to template processor
    switch (cType)
    {
        case CVerusContract::CONTRACT_SPLITTER:
        {
            CContractSplitter splitter = CContractSplitter::FromIdentity(contractIdentity);
            // Instead of creating one output to the contract address,
            // create N outputs split by shares
            auto splitOutputs = splitter.ProcessDeposit(
                oneTransfer.IsConversion() ? outputCurrencyValues : oneTransfer.IsRefund() ? ... : oneTransfer.reserveValues,
                oneTransfer.IsConversion() ? 0 : oneTransfer.IsRefund() ? 0 : oneTransfer.nValue
            );
            for (auto &out : splitOutputs)
            {
                vOutputs.push_back(out);
            }
            // Mark transfer as handled so normal output isn't created
            oneTransfer.flags |= CReserveTransfer::FEE_OUTPUT;  // reuse flag to skip
            break;
        }

        case CVerusContract::CONTRACT_ESCROW:
        {
            // Read current state UTXO
            CContractState currentState;
            // ... look up current state UTXO for this contract ...

            CContractEscrow escrow = CContractEscrow::FromIdentity(contractIdentity);

            // Determine action from gatewayCode
            uint160 actionKey = dest.gatewayCode;

            auto result = escrow.ProcessAction(actionKey, ..., height, ...);
            if (result.valid)
            {
                for (auto &out : result.outputs)
                    vOutputs.push_back(out);

                // Create new state UTXO
                CContractState newState = currentState;
                newState.blockHeight = height;
                newState.stateData[CVDXF::GetDataKey(CContractEscrow::StatusKeyName(), ...)]
                    = ::AsVector(result.newStatus);

                // Output: new contract state UTXO
                std::vector<CTxDestination> dests = {CIdentityID(destID)};
                vOutputs.push_back(CTxOut(0,
                    MakeMofNCCScript(CConditionObj<CContractState>(
                        EVAL_IDENTITY_PRIMARY, dests, 1, &newState))));
            }
            break;
        }

        case CVerusContract::CONTRACT_VESTING:
        {
            CContractVesting vesting = CContractVesting::FromIdentity(contractIdentity);
            CAmount claimable = vesting.GetClaimable(height);
            if (claimable > 0)
            {
                // Create output to beneficiary
                // Create new state UTXO with updated claimed amount
                // ...
            }
            break;
        }
    }
}
```

### 1.7 PrecheckReserveTransfer Extension

**File: `src/pbaas/pbaas.cpp`** — In `PrecheckReserveTransfer()` (line 4894), add contract-aware validation. After the existing destination checks (~line 5050), add:

```cpp
// ============================================================
// CONTRACT-BOUND TRANSFER PRECHECK
// If the destination is a contract identity, validate that the
// transfer is compatible with the contract type
// ============================================================
if (rt.destination.TypeNoFlags() == CTransferDestination::DEST_ID && haveFullChain)
{
    CIdentityID destID(rt.destination.destination);
    CIdentity destIdentity;
    if (GetIdentity(destID, destIdentity, height))
    {
        CVerusContract::EContractType cType = CVerusContract::GetContractType(destIdentity);
        if (cType != CVerusContract::CONTRACT_INVALID)
        {
            // Destination is a contract — validate
            if (destIdentity.IsRevoked())
                return state.Error("Cannot send to revoked contract identity");

            // Contract-specific precheck
            switch (cType)
            {
                case CVerusContract::CONTRACT_ESCROW:
                {
                    CContractEscrow escrow = CContractEscrow::FromIdentity(destIdentity);
                    // Reject deposits that don't match expected currency/amount
                    if (rt.IsConversion())
                        return state.Error("Cannot send conversion to escrow contract");
                    break;
                }
                case CVerusContract::CONTRACT_VESTING:
                {
                    // Only the contract creator can deposit
                    // Claims don't go TO the contract, they come FROM it
                    break;
                }
                // Splitter: accepts anything — no precheck needed
            }
        }
    }
}
```

### 1.8 Contract Creation — Identity Registration Hook

**File: `src/pbaas/identity.cpp`** — In the identity registration validation, add contract parameter validation when an identity includes `vrsc::contract.type` in its multimap.

Currently identity registration is validated in `PrecheckIdentityReservation()` and `ValidateIdentityPrimary()`. Add a check:

```cpp
// After identity is decoded from the transaction output:
if (CVerusContract::IsContract(newIdentity))
{
    CVerusContract::EContractType cType = CVerusContract::GetContractType(newIdentity);
    switch (cType)
    {
        case CVerusContract::CONTRACT_SPLITTER:
        {
            CContractSplitter splitter = CContractSplitter::FromIdentity(newIdentity);
            if (!splitter.IsValid())
                return state.Error("Invalid splitter contract: shares must sum to 10000, "
                                   "minimum 2 recipients, no duplicates");
            break;
        }
        case CVerusContract::CONTRACT_ESCROW:
        {
            CContractEscrow escrow = CContractEscrow::FromIdentity(newIdentity);
            if (!escrow.IsValid())
                return state.Error("Invalid escrow contract parameters");
            if (escrow.timeout <= height)
                return state.Error("Escrow timeout must be in the future");
            break;
        }
        // ... etc
    }
}
```

### 1.9 Identity Spending Restriction for Contracts

Contract funds must only be spendable through import processing or recovery authority — not by the identity's primary key holders directly.

**File: `src/pbaas/identity.cpp`** — Extend `ValidateIdentityPrimary` to check for contract VDXF keys when an identity's funds are being spent:

```cpp
// Inside existing ValidateIdentityPrimary, after identity is loaded:
if (CVerusContract::IsContract(identity))
{
    // Contract identity funds can only be spent by:
    // 1. An import transaction (contract action processed through consensus)
    // 2. Recovery authority (emergency override)
    // Primary key holders CANNOT directly spend contract funds

    bool isImportSpend = false;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams checkP;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(checkP) &&
            checkP.IsValid() &&
            checkP.evalCode == EVAL_CROSSCHAIN_IMPORT)
        {
            isImportSpend = true;
            break;
        }
    }

    if (!isImportSpend && !isRecoverySpend)
        return eval->Error("Contract funds can only be spent through contract actions or recovery");
}
```

This uses the existing identity spending validation path — no new eval code needed. The identity is recognized as a contract by the presence of `vrsc::contract.type` in its contentMultiMap.

### 1.10 RPC Commands

**File: `src/rpc/pbaasrpc.cpp`** — Add new RPC methods:

```cpp
// createcontract — create a contract identity with the right multimap entries
UniValue createcontract(const UniValue& params, bool fHelp)
{
    // params: type, params (type-specific), name, fees
    // Constructs the identity with contentMultiMap populated
    // Calls the existing registeridentity flow
}

// getcontract — read a contract's definition and current state
UniValue getcontract(const UniValue& params, bool fHelp)
{
    // params: identity name or i-address
    // Returns: contract type, params, current state, balance
}

// contractaction — submit an action to a contract (e.g. escrow release)
UniValue contractaction(const UniValue& params, bool fHelp)
{
    // params: contract identity, action type, signer
    // Constructs a reserve transfer with the action VDXF key in auxDests
    // Calls sendcurrency flow
}
```

### 1.11 Activation Height

**File: `src/pbaas/pbaas.h`** — Add activation timestamp like existing upgrades:

```cpp
static const uint32_t PBAAS_CONTRACT_ACTIVATION = ...; // UTC timestamp
```

**File: `src/pbaas/pbaas.cpp`** — Gate all contract logic behind activation check:

```cpp
bool CheckContractActive(uint32_t height)
{
    return CheckPastRealTime(PBAAS_TESTMODE ? PBAAS_CONTRACT_TESTNET_ACTIVATION
                                            : PBAAS_CONTRACT_ACTIVATION, height) == 1;
}
```

---

## Part 2: File Change Summary

| File | Change | Lines (est.) |
|------|--------|-------------|
| `pbaas/vdxf.h` | VDXF key constants for contract types, actions, state (~30 keys) | 300 |
| **`pbaas/contracts.h`** (new) | Contract structs, serialization, VDXF key helpers | 500 |
| **`pbaas/contracts.cpp`** (new) | Precheck dispatch, process logic per template | 1000 |
| `pbaas/reserves.cpp` | Contract dispatch in `AddReserveTransferImportOutputs` | 150 |
| `pbaas/pbaas.cpp` | Contract-aware check in `PrecheckReserveTransfer` | 60 |
| `pbaas/pbaas.h` | Activation timestamp | 5 |
| `pbaas/identity.cpp` | Contract validation at registration + spending restriction | 80 |
| `rpc/pbaasrpc.cpp` | New RPC commands (createcontract, getcontract, contractaction) | 200 |
| **Total** | | **~2300** |

No changes to `cc/eval.h`, `cc/CCcustom.cpp`, or `cc/CCaddresses.cpp` — contracts operate entirely through VDXF keys within the existing smart transaction framework.

---

## Part 3: Architecture Decisions

### 3.1 Why Separate State UTXOs (Not Multimap)

Contract state should NOT live in the identity's contentMultiMap because:

1. **Authorization model**: Identity updates require primary key signatures. Consensus-driven state changes (escrow status, vesting claimed amount) shouldn't need the owner's key — they happen automatically based on contract rules. Putting state in the identity would require the protocol to forge identity update signatures.

2. **Precedent**: Verus already separates definition from state. `CCurrencyDefinition` is the definition (static), `CCoinbaseCurrencyState` in notarizations is the state (changes each block). Same pattern here.

3. **UTXO tracking**: State UTXOs create a clean UTXO chain — each state transition spends the old state and creates a new one. This provides auditability and makes it easy to query current state.

4. **No identity output churn**: Contract activity (which could be frequent) doesn't create new identity outputs. The identity remains stable; only the state UTXO changes.

### 3.2 Why Reserve Transfers with gatewayCode for Actions

Contract actions are submitted as reserve transfers. The action is specified via `CTransferDestination.gatewayCode` — a `uint160` field that already exists for specifying "code for function to execute on the gateway." The contract identity IS the gateway; the `gatewayCode` is the VDXF key hash of the action (e.g., `vrsc::contract.action.escrow.release`).

This is cleaner than using `auxDests` because:

1. **gatewayCode exists for exactly this purpose**: It's a dedicated field for "what function to run at the destination." Using it for contract actions is using it as designed.

2. **No new transaction type needed**: Reserve transfers are already the universal "do something" mechanism. The existing export → import pipeline handles aggregation, ordering, and atomic processing.

3. **Fee infrastructure exists**: Reserve transfers already have fee validation, cross-chain routing, and the precheck pipeline.

4. **Cross-chain for free**: If a contract identity is exported to a PBaaS chain, actions can be sent cross-chain through the existing bridge. No additional cross-chain code needed.

5. **auxDests remain available**: Since gatewayCode handles the action, all 3 auxDest slots remain free for action-specific parameters (e.g., which borrower to liquidate).

### 3.3 Why VDXF Keys, Not Eval Codes

Contracts use VDXF keys rather than new eval codes because:

1. **Right abstraction layer**: Eval codes are deep protocol primitives — the lowest level of the smart transaction system. Contracts are a higher-level concept built ON those primitives. Adding an eval code for contracts would be like adding a new CPU instruction for every application.

2. **VDXF is designed for this**: VDXF keys are Verus's extensibility mechanism — they describe functions, data types, and actions without modifying the protocol core. Contract types and actions are exactly the kind of thing VDXF keys are for.

3. **Extensibility**: New contract templates can be added by defining new VDXF keys and adding dispatch cases in `contracts.cpp`. No protocol-level changes needed — no new eval codes, no new smart transaction registrations, no hard fork for each template.

4. **Identity-native recognition**: Contract identities are recognized by checking their contentMultiMap for the `vrsc::contract.type` VDXF key. This uses the existing identity infrastructure rather than requiring a parallel recognition system.

### 3.4 Transfers Must Go Through Import Pipeline

Contract logic executes during `AddReserveTransferImportOutputs`. A normal `sendtoaddress` to a contract identity creates a direct UTXO — it never hits the import pipeline, so no contract logic runs.

**Solution: Contracts only accept reserve transfers.** All interactions with a contract identity must use `sendcurrency` (which creates reserve transfers), not `sendtoaddress`. The precheck in `PrecheckReserveTransfer` validates contract-bound transfers. Direct sends to a contract identity's address are rejected by the spending restriction (section 1.9) — the funds would be stuck since only import processing or recovery can spend them.

This is enforced by:
1. **Section 1.9 spending restriction**: Contract identity UTXOs can only be spent via import or recovery. If someone sends via `sendtoaddress`, the UTXO exists but can never be spent through normal means — only recovered.
2. **RPC helper**: The `contractaction` RPC always constructs a reserve transfer, never a raw send.
3. **Wallet warning**: If a wallet detects a contract identity as destination, it should warn the user to use `sendcurrency` / `contractaction` instead.

### 3.5 State UTXO Recognition

Without a dedicated eval code, state UTXOs must be distinguishable from normal identity outputs. 

**Solution: State is stored as VDXF-structured data within the output script.** The state UTXO contains a `CContractState` object serialized as VDXF structured data (using the existing `vrsc::system.structureddata` pattern). The contract processor recognizes state UTXOs by checking for the `vrsc::contract.state` VDXF key in the output's structured data.

When the import processor needs to find the current state for a contract:
1. Look up UTXOs at the contract identity's address
2. For each UTXO, check if it contains VDXF structured data with key `vrsc::contract.state`
3. The one with the highest `blockHeight` in its `CContractState` is the current state

State UTXOs form a chain — each state transition spends the previous state UTXO and creates a new one, exactly like notarizations.

### 3.6 Contract Parameter Protection

Contract parameters (splitter shares, escrow terms, lending rates) are protected by VerusID's existing access control, not by a special immutability layer:

- **Locking** prevents direct spending of contract funds
- **Multisig** prevents unilateral parameter changes (all parties must sign updates)
- **Revocation** lets a trusted authority pause the contract
- **Recovery** provides emergency override

No additional code is needed for parameter protection — the identity's `minSigs`, primary addresses, revocation authority, and recovery authority already provide the required access control. Contract deployers choose the security model that fits their use case.

---

## Part 4: Contract Templates

### 4.1 Splitter

**Deploy:** Register identity `my-split@` with contentMultiMap:
```
vrsc::contract.type                 = VDXF_KEY("vrsc::contract.template.splitter")
vrsc::contract.splitter.recipients  = serialized vector of {destination, shareBPs}
vrsc::contract.splitter.minpayout   = int64(100000)  // 0.001 VRSC minimum
```

**Use:** Send funds to `my-split@` — import processor auto-creates split outputs.

**No state UTXO needed** — splitter is stateless, purely reactive.

### 4.2 Escrow

**Deploy:** Register identity `deal-escrow@` with contentMultiMap:
```
vrsc::contract.type              = VDXF_KEY("vrsc::contract.template.escrow")
vrsc::contract.escrow.parties    = {buyer: "alice@", seller: "bob@", arbiter: "carol@"}
vrsc::contract.escrow.amount     = int64(1000000000)  // 10 VRSC
vrsc::contract.escrow.currency   = VRSC currency ID
vrsc::contract.escrow.timeout    = uint32(4100000)  // auto-refund block
vrsc::contract.escrow.require    = uint8(1)  // buyer-only release
```

**Deposit:** `sendcurrency '*' '[{"address":"deal-escrow@","amount":10}]'`
→ Import creates state UTXO: `status = FUNDED`

**Release:** `contractaction deal-escrow@ release` (signed by buyer's key)
→ Import spends state UTXO, creates output to seller, new state: `status = RELEASED`

**Timeout:** Block 4100000 reached, no release
→ Import auto-refunds to buyer, new state: `status = REFUNDED`

### 4.3 Vesting

**Deploy:** Register identity `team-vest@` with contentMultiMap + fund it:
```
vrsc::contract.type                 = VDXF_KEY("vrsc::contract.template.vesting")
vrsc::contract.vesting.beneficiary  = "employee@"
vrsc::contract.vesting.schedule     = {amount: 100M sats, start: 4000000, cliff: 4050000,
                                       end: 4200000, interval: 1440}  // daily claims
```

**Claim:** `contractaction team-vest@ claim` (signed by beneficiary)
→ Import calculates vested amount, sends to beneficiary, updates claimed state

### 4.4 Subscription

**Deploy:** Register identity `my-sub@`:
```
vrsc::contract.type                     = VDXF_KEY("vrsc::contract.template.subscription")
vrsc::contract.subscription.provider    = "service@"
vrsc::contract.subscription.amount      = int64(100000000)  // 1 VRSC/period
vrsc::contract.subscription.currency    = VRSC
vrsc::contract.subscription.period      = uint32(43200)     // ~30 days
```

**Fund:** Subscriber sends funds to `my-sub@`

**Pull:** Provider calls `contractaction my-sub@ pull` each period
→ Precheck rejects if period hasn't elapsed

**Cancel:** Subscriber calls `contractaction my-sub@ cancel`
→ Remaining funds returned, state set to inactive

### 4.5 Conditional (Oracle-Triggered)

**Deploy:** Register identity `bet-contract@`:
```
vrsc::contract.type                      = VDXF_KEY("vrsc::contract.template.conditional")
vrsc::contract.conditional.oracle        = "weather-oracle@"
vrsc::contract.conditional.attestkey     = vrsc::oracle.attestation.event.X
vrsc::contract.conditional.recipient     = "alice@"
vrsc::contract.conditional.fallback      = "bob@"
vrsc::contract.conditional.timeout       = uint32(4100000)
```

**Trigger:** When `weather-oracle@` updates its own multimap with the attestation key
→ Import detects attestation, releases funds to recipient

**Timeout:** Block 4100000 reached without attestation
→ Funds go to fallback address

### 4.6 Lending Pool (`vrsc::contract.template.lending`)

Collateralized lending using basket conversion prices as on-chain oracle — no external price feed needed.

**Why Verus can do this without Turing completeness:**
Ethereum lending protocols (Aave, Compound) need Chainlink oracles for price feeds. Verus basket currencies already have `lastconversionprice` and `viaconversionprice` updated every block by actual market activity in `CCoinbaseCurrencyState`. These prices are consensus-level, manipulation-resistant (you'd have to move real reserves), and already used for reserve-to-reserve conversions. The lending template reads these directly — zero oracle infrastructure needed.

**Parameters:**
```
vrsc::contract.type                     = VDXF_KEY("vrsc::contract.template.lending")
vrsc::contract.lending.collateral       = [uint160]  // accepted collateral currency IDs
vrsc::contract.lending.borrow           = [uint160]  // lendable currency IDs
vrsc::contract.lending.pricefeed        = uint160    // basket currency ID whose conversion prices are the oracle
vrsc::contract.lending.ltv              = uint32     // max loan-to-value in basis points (e.g. 7500 = 75%)
vrsc::contract.lending.liquidation      = uint32     // liquidation threshold in basis points (e.g. 8500 = 85%)
vrsc::contract.lending.liquidationbonus = uint32     // bonus for liquidators in basis points (e.g. 500 = 5%)
vrsc::contract.lending.interestmodel    = serialized {baseRate, slope1, slope2, kink}
  // Two-slope interest model (like Compound):
  // if utilization <= kink: rate = baseRate + utilization * slope1
  // if utilization >  kink: rate = baseRate + kink * slope1 + (utilization - kink) * slope2
  // All values in basis points per block
vrsc::contract.lending.maxpositions     = uint32     // max concurrent borrow positions (caps state size)
```

**State:**
```
vrsc::contract.state.lending.pool       = serialized {
  totalDeposited:    CCurrencyValueMap   // total lender deposits by currency
  totalBorrowed:     CCurrencyValueMap   // total outstanding borrows by currency
  lastAccrualHeight: uint32             // last block interest was accrued
  accumulatedRate:   int64[]            // accumulated interest rate per currency (scaled by 1e18)
}

vrsc::contract.state.lending.position   = [multiple entries, one per borrower]
  Each entry (serialized):
    borrower:        uint160            // borrower identity ID
    collateralCurrency: uint160
    collateralAmount:   int64
    borrowCurrency:  uint160
    borrowAmount:    int64              // principal at time of borrow
    entryRate:       int64              // accumulatedRate at time of borrow (for interest calc)
```

**C++ Data Structure:**

```cpp
class CContractLending
{
public:
    struct InterestModel
    {
        uint32_t baseRateBP;    // base rate per block in basis points (scaled 1e8)
        uint32_t slope1BP;      // slope below kink
        uint32_t slope2BP;      // slope above kink
        uint32_t kinkBP;        // utilization kink point (basis points, e.g. 8000 = 80%)

        // Calculate per-block interest rate given utilization (0-10000 BP)
        int64_t GetRate(uint32_t utilizationBP) const
        {
            if (utilizationBP <= kinkBP)
                return baseRateBP + ((int64_t)utilizationBP * slope1BP) / 10000;
            else
                return baseRateBP + ((int64_t)kinkBP * slope1BP) / 10000
                     + ((int64_t)(utilizationBP - kinkBP) * slope2BP) / 10000;
        }

        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(VARINT(baseRateBP));
            READWRITE(VARINT(slope1BP));
            READWRITE(VARINT(slope2BP));
            READWRITE(VARINT(kinkBP));
        }
    };

    struct Position
    {
        uint160 borrowerID;
        uint160 collateralCurrencyID;
        int64_t collateralAmount;
        uint160 borrowCurrencyID;
        int64_t borrowAmount;
        int64_t entryRate;              // accumulatedRate snapshot at borrow time

        // Current debt = borrowAmount * (currentAccumulatedRate / entryRate)
        int64_t GetCurrentDebt(int64_t currentAccumulatedRate) const
        {
            if (entryRate <= 0) return borrowAmount;
            return (int64_t)((__int128)borrowAmount * currentAccumulatedRate / entryRate);
        }

        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(borrowerID);
            READWRITE(collateralCurrencyID);
            READWRITE(VARINT(collateralAmount));
            READWRITE(borrowCurrencyID);
            READWRITE(VARINT(borrowAmount));
            READWRITE(VARINT(entryRate));
        }
    };

    std::vector<uint160> collateralCurrencies;
    std::vector<uint160> borrowCurrencies;
    uint160 priceFeedBasket;                    // basket whose prices are the oracle
    uint32_t maxLTV;                            // basis points
    uint32_t liquidationThreshold;              // basis points
    uint32_t liquidationBonus;                  // basis points
    InterestModel interestModel;
    uint32_t maxPositions;

    // Price lookup: read from basket currency state (no external oracle)
    // Returns price of currencyID in terms of the basket's native reserve
    static int64_t GetPrice(const uint160 &currencyID, const uint160 &basketID, uint32_t height)
    {
        // Read the basket's latest currency state from the notarization chain
        CCoinbaseCurrencyState basketState = ConnectedChains.GetCurrencyState(basketID, height);
        auto reserveMap = basketState.GetReserveMap();
        auto it = reserveMap.find(currencyID);
        if (it == reserveMap.end()) return 0;
        int index = it->second;
        if (index < 0 || index >= basketState.conversionPrice.size()) return 0;
        return basketState.conversionPrice[index];
    }

    // Collateral ratio = (collateral * collateralPrice) / (debt * borrowPrice)
    // Returns basis points (10000 = 100%)
    uint32_t GetCollateralRatioBP(const Position &pos, int64_t currentAccumulatedRate, uint32_t height) const
    {
        int64_t debt = pos.GetCurrentDebt(currentAccumulatedRate);
        if (debt <= 0) return 10000;
        int64_t collateralValue = ((__int128)pos.collateralAmount * GetPrice(pos.collateralCurrencyID, priceFeedBasket, height)) / SATOSHIDEN;
        int64_t debtValue = ((__int128)debt * GetPrice(pos.borrowCurrencyID, priceFeedBasket, height)) / SATOSHIDEN;
        if (debtValue <= 0) return 10000;
        return (uint32_t)(((__int128)collateralValue * 10000) / debtValue);
    }

    static std::string PoolKeyName()        { return "vrsc::contract.lending.pool"; }
    static std::string PositionKeyName()    { return "vrsc::contract.state.lending.position"; }
    static std::string ActionDepositKeyName()   { return "vrsc::contract.action.lending.deposit"; }
    static std::string ActionBorrowKeyName()    { return "vrsc::contract.action.lending.borrow"; }
    static std::string ActionRepayKeyName()     { return "vrsc::contract.action.lending.repay"; }
    static std::string ActionWithdrawKeyName()  { return "vrsc::contract.action.lending.withdraw"; }
    static std::string ActionLiquidateKeyName() { return "vrsc::contract.action.lending.liquidate"; }

    static CContractLending FromIdentity(const CIdentity &identity);
    bool IsValid() const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(collateralCurrencies);
        READWRITE(borrowCurrencies);
        READWRITE(priceFeedBasket);
        READWRITE(VARINT(maxLTV));
        READWRITE(VARINT(liquidationThreshold));
        READWRITE(VARINT(liquidationBonus));
        READWRITE(interestModel);
        READWRITE(VARINT(maxPositions));
    }
};
```

**Import Processing:**

```cpp
case CVerusContract::CONTRACT_LENDING:
{
    CContractLending lending = CContractLending::FromIdentity(contractIdentity);
    CContractState currentState; // read from state UTXO chain

    // Accrue interest first — update accumulatedRate for all blocks since lastAccrualHeight
    uint32_t blocksSinceAccrual = height - currentState.lastAccrualHeight;
    if (blocksSinceAccrual > 0)
    {
        for (auto &currency : lending.borrowCurrencies)
        {
            int64_t totalDeposited = /* from state */;
            int64_t totalBorrowed = /* from state */;
            uint32_t utilization = totalDeposited > 0
                ? (uint32_t)((int64_t)totalBorrowed * 10000 / totalDeposited)
                : 0;
            int64_t ratePerBlock = lending.interestModel.GetRate(utilization);
            // Compound: accumulatedRate *= (1 + ratePerBlock)^blocks
            // PRECISION NOTE: With large block gaps (1000+ blocks between interactions),
            // naive exponentiation overflows. Use exponentiation by squaring with __int128
            // intermediate values, scaled by 1e18. The existing Verus codebase uses
            // cpp_dec_float_50 for similar calculations in CalculateFractionalOut() —
            // the same approach should be used here for consistency and safety.
        }
    }

    // Dispatch action
    uint160 actionKey = /* from auxDests */;

    if (actionKey == depositKey)
    {
        // Lender deposits funds into pool
        // Update totalDeposited in state
        // Create pool share tracking for this lender
    }
    else if (actionKey == borrowKey)
    {
        // Borrower has sent collateral in this transfer
        // Check LTV: collateralValue * maxLTV / 10000 >= borrowAmount * borrowPrice
        // Create Position in state
        // Create output: borrowed amount to borrower
    }
    else if (actionKey == repayKey)
    {
        // Borrower repays debt (transfer contains repayment amount)
        // Calculate current debt with interest
        // Update or close Position
        // Return collateral if fully repaid
    }
    else if (actionKey == withdrawKey)
    {
        // Lender withdraws from pool
        // Check available liquidity (deposited - borrowed)
        // Create output: withdrawn amount to lender
    }
    else if (actionKey == liquidateKey)
    {
        // Anyone can liquidate an undercollateralized position
        // Check: GetCollateralRatioBP(position) < liquidationThreshold
        // Liquidator pays off debt, receives collateral + bonus
        // Uses basket conversion prices for all valuations
        //
        // This is manipulation-resistant because moving basket prices
        // requires actual reserve deposits/withdrawals — you can't
        // fake a price to trigger liquidation without putting up real money
    }

    // Write updated state UTXO
    break;
}
```

**Precheck:**

```cpp
case CVerusContract::CONTRACT_LENDING:
{
    CContractLending lending = CContractLending::FromIdentity(contractIdentity);

    if (actionKey == borrowKey)
    {
        // Reject if collateral currency not in accepted list
        // Reject if borrow currency not in lendable list
        // Reject if collateral amount is 0
        // Reject if maxPositions would be exceeded
    }
    else if (actionKey == liquidateKey)
    {
        // Read position from state
        // Read current prices from basket
        // Reject if position is NOT undercollateralized (healthy position)
        // This prevents griefing — can't liquidate someone who's fine
    }
    else if (actionKey == withdrawKey)
    {
        // Reject if withdrawal would make pool insolvent
        // (can't withdraw more than deposited - borrowed)
    }
    return true;
}
```

**Deploy:**
```
verus createcontract '{
  "type": "lending",
  "name": "vrsc-lending-pool",
  "collateral": ["DAI", "vETH", "MKR"],
  "borrow": ["VRSC"],
  "pricefeed": "Bridge.vETH",
  "ltv": 7500,
  "liquidation": 8500,
  "liquidationbonus": 500,
  "interest": {"base": 200, "slope1": 400, "slope2": 7500, "kink": 8000},
  "maxpositions": 1000
}'
```

**User flow:**
```bash
# Lender deposits 1000 VRSC into pool
verus contractaction vrsc-lending-pool@ deposit \
  '{"currency":"VRSC","amount":1000}'

# Borrower deposits 10 vETH collateral, borrows 500 VRSC
verus contractaction vrsc-lending-pool@ borrow \
  '{"collateral":"vETH","collateralAmount":10,"borrow":"VRSC","borrowAmount":500}'

# Borrower repays 505 VRSC (principal + interest)
verus contractaction vrsc-lending-pool@ repay \
  '{"currency":"VRSC","amount":505}'

# Anyone can liquidate if collateral ratio drops below 85%
verus contractaction vrsc-lending-pool@ liquidate \
  '{"borrower":"defaulter@"}'
```

**Why basket prices work as oracle:**

On Ethereum, Chainlink is needed because there's no native price source. On Verus, every basket currency maintains `conversionPrice[]` in its `CCoinbaseCurrencyState`, updated every block through actual reserve conversions. These prices are:

1. **Consensus-level** — all nodes agree on the same prices
2. **Manipulation-resistant** — moving a price requires depositing/withdrawing real reserves from the basket. An attacker can't flash-loan their way to a fake price because there are no flash loans on UTXO.
3. **Always available** — no oracle downtime, no stale prices, no need to trust a third party
4. **Already used for conversions** — the same prices that execute reserve-to-reserve swaps

The lending template's `priceFeedBasket` parameter points to a basket (like `Bridge.vETH`) that contains the relevant currencies. The `GetPrice()` function reads `conversionPrice[i]` directly from the basket's latest notarization. No external infrastructure.

---

### What Verus Already Handles Natively (No Templates Needed)

These common smart contract use cases are already consensus features:

| Use Case | Verus Native Feature |
|----------|---------------------|
| **Tokens (ERC-20)** | `definecurrency` — any token with built-in conversion |
| **DEX / AMM** | Basket currencies with fractional reserves |
| **Stablecoins** | Reserve-backed baskets (e.g., DAI.vETH) |
| **Bridges** | PBaaS + Ethereum bridge — trustless cross-chain |
| **Multisig** | VerusID `minSigs` + multiple primary addresses |
| **Fundraising / ICO** | Preconversion phase of currency launches |
| **Governance** | `EVAL_VOTING_GOVERNANCE`, `EVAL_VOTING_VOTE`, `EVAL_VOTING_POLL` |
| **Dead Man's Switch** | VerusID `unlockAfter` timelock — funds locked until block/time |
| **Rate Limiting** | VerusID timelock + spending conditions |
| **Time-Delayed Vault** | VerusID timelock — all spends delayed, revocation can cancel |
| **Key Recovery** | VerusID recovery authority — change keys without moving funds |

These don't need templates because they're already baked into the protocol at the consensus level.

---

## Part 5: Upgrade Path

### Phase 1: Splitter Only
- Simplest template, stateless, no actions
- Validates the full pipeline: identity creation → contract detection → import processing → split outputs
- ~500 lines of new code
- Low risk — doesn't modify any existing behavior

### Phase 2: Escrow + Vesting
- Introduces stateful contracts (state UTXOs)
- Introduces the action mechanism (auxDest VDXF keys)
- ~800 lines additional

### Phase 3: Subscription + Conditional
- Builds on Phase 2 infrastructure
- Introduces time-based auto-triggers (subscription pulls, conditional timeouts)
- ~400 lines additional

### Phase 4: Lending
- Most complex template — multi-position state, interest accrual, liquidation
- Depends on Phase 2 infrastructure (state UTXOs, actions)
- Uses basket conversion prices as oracle (no new price infrastructure)
- ~600 lines additional
- Should be heavily tested on testnet — lending bugs can lose real funds
