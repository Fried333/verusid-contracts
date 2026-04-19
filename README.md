# Verus Deterministic Contract Standard (VCS)
## Non-Turing-Complete Smart Contracts via VerusID Content Multimap

### Overview

A Verus Contract is a VerusID whose `contentMultiMap` declares a contract type and its parameters. The protocol interprets these declarations through existing CC eval infrastructure — no virtual machine, no bytecode, no Turing completeness. Each contract type is a known template with a precheck validator and an import-time executor, following the same architecture as reserve transfers and basket conversions.

---

## Part 1: Code Changes Required

### 1.1 New Eval Code

**File: `src/cc/eval.h`** — Add one new eval code after the existing ones:

```cpp
// Current last entry is EVAL_QUANTUM_KEY = 0x1a
EVAL(EVAL_CONTRACT_SPEND, 0x1b)    // spending from a contract-bound identity
```

This eval code is used on UTXOs held by a contract identity. When a UTXO is sent to an identity that has `vrsc::contract.type` in its multimap, the output is created with `EVAL_CONTRACT_SPEND` instead of normal `EVAL_IDENTITY_PRIMARY`. This makes the funds spendable only through contract rules, not by the identity's primary key holders directly.

### 1.2 CC Registration

**File: `src/cc/CCcustom.cpp`** — Register in the switch statement alongside existing eval codes:

```cpp
case EVAL_CONTRACT_SPEND:
    strcpy(cp->unspendableCCaddr, ContractSpendAddr.c_str());
    strcpy(cp->normaladdr, ContractSpendAddr.c_str());
    strcpy(cp->CChexstr, ContractSpendPubKey.c_str());
    memcpy(cp->CCpriv, DecodeSecret(ContractSpendWIF).begin(), 32);
    cp->validate = ValidateContractSpend;
    cp->ismyvin = IsContractSpendInput;
    cp->contextualprecheck = PrecheckContractSpend;
    break;
```

Requires generating a new CC address/pubkey/WIF triplet, same as the existing ones in `CCaddresses.cpp`.

### 1.3 New Contract Data Structure

**New file: `src/pbaas/contracts.h`**

```cpp
#include "identity.h"
#include "reserves.h"
#include "vdxf.h"

// Contract template identifiers — each maps to a uint160 VDXF key
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
    };

    // VDXF key names for contract namespace
    static std::string ContractTypeKeyName()        { return "vrsc::contract.type"; }
    static std::string ContractVersionKeyName()     { return "vrsc::contract.version"; }

    // Read contract type from an identity's contentMultiMap
    // Returns CONTRACT_INVALID if identity is not a contract
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

### 1.4 VDXF Key Registration

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

### 1.5 Contract State — Separate UTXO (Recommended)

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

The state UTXO uses `EVAL_CONTRACT_SPEND` and is held at the contract identity's address. On each state transition, the import processor spends the old state UTXO and creates a new one with updated values. This is exactly how notarizations work — each new notarization spends the previous one.

### 1.6 Precheck Function

**File: `src/pbaas/contracts.cpp`** (new file)

```cpp
#include "contracts.h"
#include "pbaas.h"

// Called by CC infrastructure when a EVAL_CONTRACT_SPEND output is being spent
bool PrecheckContractSpend(const CTransaction &tx, int32_t outNum,
                           CValidationState &state, uint32_t height)
{
    // 1. Decode the spending transaction — find the import or action
    COptCCParams p;
    if (!tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) || !p.IsValid())
        return state.Error("Invalid contract spend output");

    // 2. Find which identity this contract belongs to
    //    The output address tells us the contract identity
    CTxDestination dest;
    if (!ExtractDestination(tx.vout[outNum].scriptPubKey, dest))
        return state.Error("Cannot extract contract identity from output");

    CIdentityID contractID = GetDestinationID(dest);

    // 3. Look up the identity and read contract type
    CIdentity contractIdentity;
    // Use ConnectedChains or view to get the identity
    if (!GetIdentity(contractID, contractIdentity, height))
        return state.Error("Contract identity not found");

    if (contractIdentity.IsRevoked())
        return state.Error("Contract identity is revoked — contract paused");

    CVerusContract::EContractType cType = CVerusContract::GetContractType(contractIdentity);
    if (cType == CVerusContract::CONTRACT_INVALID)
        return state.Error("Identity is not a contract");

    // 4. Dispatch to type-specific precheck
    switch (cType)
    {
        case CVerusContract::CONTRACT_SPLITTER:
        {
            CContractSplitter splitter = CContractSplitter::FromIdentity(contractIdentity);
            if (!splitter.IsValid())
                return state.Error("Invalid splitter contract parameters");
            // Splitter has no actions — funds are auto-split on deposit
            // Precheck: verify the spending tx is an import transaction
            return PrecheckSplitterSpend(tx, outNum, state, height, splitter);
        }

        case CVerusContract::CONTRACT_ESCROW:
        {
            CContractEscrow escrow = CContractEscrow::FromIdentity(contractIdentity);
            if (!escrow.IsValid())
                return state.Error("Invalid escrow contract parameters");
            return PrecheckEscrowSpend(tx, outNum, state, height, escrow);
        }

        case CVerusContract::CONTRACT_VESTING:
        {
            CContractVesting vesting = CContractVesting::FromIdentity(contractIdentity);
            if (!vesting.IsValid())
                return state.Error("Invalid vesting contract parameters");
            return PrecheckVestingSpend(tx, outNum, state, height, vesting);
        }

        default:
            return state.Error("Unknown contract type");
    }
}

// Example: Escrow precheck
bool PrecheckEscrowSpend(const CTransaction &tx, int32_t outNum,
                         CValidationState &state, uint32_t height,
                         const CContractEscrow &escrow)
{
    // Find the action key in the spending transaction's reserve transfer auxdests
    uint160 actionKey;
    // ... extract from tx inputs ...

    if (actionKey == CVDXF::GetDataKey(CContractEscrow::ActionReleaseKeyName(), ...))
    {
        // Release: verify signer is buyer (or buyer+seller depending on requiredSigs)
        if (escrow.status != CContractEscrow::STATUS_FUNDED)
            return state.Error("Escrow not in funded state — cannot release");

        // Verify the spending transaction is signed by the buyer
        // (check vin signatures against escrow.buyer)
        // ...
        return true;
    }
    else if (actionKey == CVDXF::GetDataKey(CContractEscrow::ActionDisputeKeyName(), ...))
    {
        if (escrow.status != CContractEscrow::STATUS_FUNDED)
            return state.Error("Escrow not in funded state — cannot dispute");
        if (!escrow.arbiter.IsValid())
            return state.Error("No arbiter defined for this escrow");
        return true;
    }

    // Timeout auto-refund: no action needed, import processor handles it
    if (height >= escrow.timeout && escrow.status == CContractEscrow::STATUS_FUNDED)
        return true;

    return state.Error("Invalid escrow action");
}
```

### 1.7 Import Processing — Extend AddReserveTransferImportOutputs

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

            // Determine action from auxDests
            uint160 actionKey;
            if (dest.AuxDestCount() > 0)
            {
                CTransferDestination auxDest;
                dest.GetAuxDest(auxDest, 0);
                actionKey = CIdentityID(auxDest.destination);
            }

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
                        EVAL_CONTRACT_SPEND, dests, 1, &newState))));
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

### 1.8 PrecheckReserveTransfer Extension

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

### 1.9 Contract Creation — Identity Registration Hook

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

### 1.10 ValidateContractSpend

**File: `src/pbaas/contracts.cpp`**

```cpp
// Called when a EVAL_CONTRACT_SPEND UTXO is being spent
// Ensures spending is only allowed through valid import transactions
bool ValidateContractSpend(struct CCcontract_info *cp, Eval* eval,
                           const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // Contract funds can only be spent by:
    // 1. An import transaction (EVAL_CROSSCHAIN_IMPORT in one of the outputs)
    //    — this means the contract action was processed through proper consensus
    // 2. Recovery authority (emergency recovery of contract identity)

    bool hasImport = false;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams checkP;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(checkP) &&
            checkP.IsValid() &&
            checkP.evalCode == EVAL_CROSSCHAIN_IMPORT)
        {
            hasImport = true;
            break;
        }
    }

    if (!hasImport)
    {
        // Check if this is a recovery spend by the recovery authority
        // ... (similar to existing identity recovery validation)
        return eval->Error("Contract funds can only be spent through import processing");
    }

    return true;
}
```

### 1.11 RPC Commands

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

### 1.12 Activation Height

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
| `cc/eval.h` | Add `EVAL_CONTRACT_SPEND` | 1 |
| `cc/CCcustom.cpp` | Register eval code | 10 |
| `cc/CCaddresses.cpp` | New CC address/pubkey/WIF | 3 |
| `pbaas/vdxf.h` | VDXF key constants (~20 keys) | 200 |
| **`pbaas/contracts.h`** (new) | Contract structs, serialization | 400 |
| **`pbaas/contracts.cpp`** (new) | Precheck, validate, process logic | 800 |
| `pbaas/reserves.cpp` | Contract dispatch in `AddReserveTransferImportOutputs` | 150 |
| `pbaas/pbaas.cpp` | Contract check in `PrecheckReserveTransfer` | 50 |
| `pbaas/pbaas.h` | Activation timestamp | 5 |
| `pbaas/identity.cpp` | Contract validation at registration | 50 |
| `rpc/pbaasrpc.cpp` | New RPC commands | 200 |
| **Total** | | **~1870** |

---

## Part 3: Architecture Decisions

### 3.1 Why Separate State UTXOs (Not Multimap)

Contract state should NOT live in the identity's contentMultiMap because:

1. **Authorization model**: Identity updates require primary key signatures. Consensus-driven state changes (escrow status, vesting claimed amount) shouldn't need the owner's key — they happen automatically based on contract rules. Putting state in the identity would require the protocol to forge identity update signatures.

2. **Precedent**: Verus already separates definition from state. `CCurrencyDefinition` is the definition (static), `CCoinbaseCurrencyState` in notarizations is the state (changes each block). Same pattern here.

3. **UTXO tracking**: State UTXOs create a clean UTXO chain — each state transition spends the old state and creates a new one. This provides auditability and makes it easy to query current state.

4. **No identity output churn**: Contract activity (which could be frequent) doesn't create new identity outputs. The identity remains stable; only the state UTXO changes.

### 3.2 Why Reuse Reserve Transfers for Actions

Actions are submitted as reserve transfers with action VDXF keys in `auxDests` because:

1. **No new transaction type needed**: Reserve transfers are already the universal "do something" mechanism. The existing export → import pipeline handles aggregation, ordering, and atomic processing.

2. **Fee infrastructure exists**: Reserve transfers already have fee validation, cross-chain routing, and the precheck pipeline.

3. **auxDests already exist**: `CTransferDestination.auxDests` supports up to 3 auxiliary destinations (checked at line 4920 of pbaas.cpp). Using one slot for a VDXF action key is a natural extension — the action key is just another `DEST_ID` pointing to a VDXF key hash.

4. **Cross-chain for free**: If a contract identity is exported to a PBaaS chain, actions can be sent cross-chain through the existing bridge. No additional cross-chain code needed.

### 3.3 Why One Eval Code (Not One Per Template)

A single `EVAL_CONTRACT_SPEND` eval code with internal dispatch is preferable to one eval code per template because:

1. **Eval codes are scarce**: Only 256 possible (uint8). Currently 26 are used. Each new template type shouldn't consume one.

2. **Same validation pattern**: All contract spends follow the same pattern (must be via import or recovery). The type-specific logic is in the import processor, not the spend validator.

3. **Extensibility**: New contract templates can be added without touching eval.h or CCcustom.cpp — just add a new case to the dispatch switch.

---

## Part 4: Contract Templates

### 4.1 Splitter

**Deploy:** Register identity `my-split@` with contentMultiMap:
```
vrsc::contract.type                 = uint8(1)  // CONTRACT_SPLITTER
vrsc::contract.splitter.recipients  = serialized vector of {destination, shareBPs}
vrsc::contract.splitter.minpayout   = int64(100000)  // 0.001 VRSC minimum
```

**Use:** Send funds to `my-split@` — import processor auto-creates split outputs.

**No state UTXO needed** — splitter is stateless, purely reactive.

### 4.2 Escrow

**Deploy:** Register identity `deal-escrow@` with contentMultiMap:
```
vrsc::contract.type              = uint8(2)  // CONTRACT_ESCROW
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
vrsc::contract.type                 = uint8(3)  // CONTRACT_VESTING
vrsc::contract.vesting.beneficiary  = "employee@"
vrsc::contract.vesting.schedule     = {amount: 100M sats, start: 4000000, cliff: 4050000,
                                       end: 4200000, interval: 1440}  // daily claims
```

**Claim:** `contractaction team-vest@ claim` (signed by beneficiary)
→ Import calculates vested amount, sends to beneficiary, updates claimed state

### 4.4 Subscription

**Deploy:** Register identity `my-sub@`:
```
vrsc::contract.type                     = uint8(4)
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
vrsc::contract.type                      = uint8(5)
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
