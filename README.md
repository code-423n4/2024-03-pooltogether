# PoolTogether audit details
- Total Prize Pool: $36,500 in USDC
  - HM awards: $24,750 in USDC
  - Analysis awards: $1,500 in USDC
  - QA awards: $750 in USDC
  - Bot Race awards: $2,250 in USDC
  - Gas awards: $750 in USDC
  - Judge awards: $3,600 in USDC
  - Lookout awards: $2,400 USDC 
  - Scout awards: $500 in USDC
 
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/contests/2024-03-pooltogether/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts March 4, 2024 20:00 UTC
- Ends March 11, 2024 20:00 UTC

## Automated Findings / Publicly Known Issues

The 4naly3er report can be found [here](https://github.com/code-423n4/2024-03-pooltogether/blob/main/4naly3er-report.md).

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2024-03-pooltogether/blob/main/bot-report.md) within 24 hours of audit opening.

_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

### Known Yield Vault Compatibility Issues

The prize vault requires an underlying ERC4626 yield vault to earn yield on deposits, but due to the nature of the prize vault some yield vaults will not be compatible. The following is a list of known compatibility issues with yield vaults:

- The yield vault MUST NOT have any fees on deposit, withdraw, or any any other fees that would lessen the withdrawable assets compared to the balance that was deposited.
- The underlying asset MUST NOT have any fees on transfer.
- Underlying assets with low precision relative to their $ value are NOT compatible (ex. GUSD, WBTC). The prize vault attempts to minimize yield vault rounding errors and cover the remaining errors with yield so that depositors can withdraw their full deposit during normal operating conditions. As a result, certain underlying assets with low precision are not compatible if the smallest rounding error can be exploited by an attacker to deny yield generation for the prize vault. For example, GUSD is not compatible since it's a two decimal USD stablecoin and a single unit rounding error amounts to `$0.01`, which can be exploited on low-gas networks. Similarly, WBTC may not be compatible on some networks since a single unit rounding error may be large enough to exploit on low gas networks `($62k / (10^8)) = $0.00062`. As a rule of thumb, any asset with a precision per dollar ratio that is smaller than USDC is likely to be incompatible. This will vary depending on network gas costs, yield rates, and asset price volatility. Refer to the comments on the `PrizeVault.yieldBuffer` variable for more information.

### Other Known Issues

- The total supply of the prize vault shares cannot exceed max UINT96 due to limitations of the TwabController.
- The deployer of a prize vault is expected to donate assets equal to `PrizeVault.yieldBuffer` to cover initial rounding errors until they can be covered automatically by yield generation.


# Overview

> This audit is for the PoolTogether V5 `PrizeVault` contract, factory and inherited contracts. The `PrizeVault` is a redesigned and refactored version of the previous [`Vault`](https://github.com/GenerationSoftware/pt-v5-vault/blob/3d082a29f26d060cfd0a75fc13861b62bf9d3699/src/Vault.sol) contract, which was discovered to have integration issues with various underlying yield vaults. The new prize vault is designed to be fully compliant with the ERC4626 specification and to interface cleanly with as many underlying yield vaults as possible.

The `PrizeVault` takes deposits of an asset and earns yield with the deposits through an underlying yield vault. The yield is then expected to be liquidated and contributed to the prize pool as prize tokens. The depositors of the prize vault will then be eligible to win prizes from the pool. If a prize is won, The permitted claimer contract for the prize vault will claim the prize on behalf of the winner. Depositors can also set custom hooks that are called directly before and after their prize is claimed.

Share balances are stored in the `TwabController` contract through the use of the `TwabERC20` extension.

Depositors should always expect to be able to withdraw their full deposit amount and no more as long as global withdrawal limits meet or exceed their balance. However, if the underlying yield source loses assets, depositors will only be able to withdraw a proportional amount of remaining assets based on their share balance and the total debt balance.

The prize vault is designed to embody the "no loss" spirit of PoolTogether, down to the last wei. Most ERC4626 yield vaults incur small, necessary rounding errors on deposit and withdrawal to ensure the internal accounting cannot be taken advantage of. The prize vault employs two strategies in an attempt to cover these rounding errors with yield to ensure that depositors can withdraw every last wei of their initial deposit:

1. The **"dust collection strategy"**: Rounding errors are directly related to the exchange rate of the underlying yield vault; the more assets a single yield vault share is worth, the more severe the rounding errors can become. For example, if the exchange rate is 100 assets for 1 yield vault share and we assume 0 decimal precision; if alice deposits 199 assets, the yield vault will round down on the conversion and mint alice 1 share, essentially donating the remaining 99 assets to the yield vault. This behavior can open pathways for exploits in the prize vault since a bad actor could repeatedly make deposits and withdrawals that result in large rounding errors and since the prize vault covers rounding errors with yield, the attacker could withdraw without loss while essentially donating the yield back to the yield vault. To mitigate this issue, the prize vault calculates the amount of yield vault shares that would be minted during a deposit, but mints those shares directly instead, ensuring that only the exact amount of assets needed are sent to the yield vault while keeping the remainder as a latent balance in the prize vault until it can be used in the next deposit or withdraw. An inverse strategy is also used when withdrawing assets from the yield vault. This reduces the possible rounding errors to just 1 wei per deposit or withdraw.

2. The **"yield buffer"**: Since the prize vault can still incur minimal rounding errors from the yield vault, a yield buffer is required to ensure that there is always enough yield reserved to cover the rounding errors on deposits and withdrawals. This buffer should never run dry during normal operating conditions and expected yield rates. If the yield buffer is ever depleted, new deposits will be prevented and the prize vault will enter a lossy withdrawal state where depositors will incur the rounding errors on withdraw.

The prize vault does not support underlying yield vaults that take a fee on deposit or withdraw.

## Links

- **Previous audits:** 
  - [code4rena 2023-07-pooltogether](https://code4rena.com/reports/2023-07-pooltogether) (this was for a previous vault contract, but some concepts are still relevant)
- **Documentation:**
  - [PoolTogether Dev Docs](https://dev.pooltogether.com/)
  - [PoolTogether User Docs](https://docs.pooltogether.com/welcome/master)
  - [Cabana.fi Docs](https://docs.cabana.fi/)
- **Website:**
  - [PoolTogether.com](https://pooltogether.com/)
  - [Cabana.fi](https://cabana.fi/)
- **Twitter:** 
  - https://twitter.com/PoolTogether_
- **Discord:** 
  - https://pooltogether.com/discord

# Scope

| Contract | SLOC | Purpose | External Calls | Libraries used |  
| ----------- | ----------- | ----------- | ----------- | ----------- |
| [PrizeVault.sol](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol) | 435 | The prize vault takes user deposits and earns yield to generate prizes for users to win. | `PrizePool` `TwabController` `ERC4626(yieldVault)` `ERC20(asset)` | [`openzeppelin/*`](https://openzeppelin.com/contracts/) [`owner-manager-contracts/*`](https://github.com/pooltogether/owner-manager-contracts) |
| [PrizeVaultFactory.sol](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVaultFactory.sol) | 55 | The prize vault factory makes it easy to deploy a new prize vault with an underlying yield vault. |  | [`openzeppelin/*`](https://openzeppelin.com/contracts/) |
| [TwabERC20.sol](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/TwabERC20.sol) | 57 | An ERC20 token that stores balances in a PoolTogether TwabController. | `TwabController` | [`openzeppelin/*`](https://openzeppelin.com/contracts/) |
| [Claimable.sol](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/abstract/Claimable.sol) | 66 | An extension for vaults that want to enable automatic prize claims using an external claimer. | `PrizePool` `IVaultHooks` |  |
| [HookManager.sol](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/abstract/HookManager.sol) | 13 | A contract for users to manage their prize hooks on a vault. |  |  |
| [IVaultHooks.sol](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/interfaces/IVaultHooks.sol) | 22 | An interface for a vault prize hook implementation. |  |  |

## Out of scope

In addition to external libraries, the following PoolTogether contracts may be referenced in the code, but not in scope for this audit:

- [PrizePool](https://github.com/GenerationSoftware/pt-v5-prize-pool)
- [TwabController](https://github.com/GenerationSoftware/pt-v5-twab-controller)
- [LiquidationPair](https://github.com/GenerationSoftware/pt-v5-cgda-liquidator)
- [Claimer](https://github.com/GenerationSoftware/pt-v5-claimer)

# Additional Context

## Expected ERC20 Assets

- any asset that does not have fee on transfer and has ample precision as noted in the yield buffer comments

## Expected ERC4626 Yield Vaults

- any yield vault that does not have fee on deposit / withdraw / transfer, or any other fee, and is not expected to lose assets

## Expected Network Deployments

- Optimism
- Arbitrum
- Base
- Ethereum
- Other EVM Chains TBD

## Trusted Roles

The vault owner can change the yield liquidation strategy as well as the claimer strategy and permissions.

## DOS

If an attacker can deny yield accrual for an entire day or longer, this would be a sign of concern.

## ERC Standards

- `PrizeVault`: `ERC4626`
- `TwabERC20`: `ERC20`

## Attack ideas (Where to look for bugs)

- Accounting Issues
- TwabERC20 ERC20 standard compliance
- PrizeVault ERC4626 standard compliance
- Reentrancy Exploits (deposits, withdrawals, prize hooks)
- Yield Source Integration Compatibility (ex. how is asset loss handled? what can break the integration?)
  - [Yearn V3](https://github.com/yearn/yearn-vaults-v3)
  - [Beefy](https://docs.beefy.finance/developer-documentation/other-beefy-contracts/beefywrapper-contract)
  - [sDAI](https://docs.spark.fi/defi-infrastructure/sdai-overview)
  - [Yield Daddy Aave V3 Wrapper](https://github.com/timeless-fi/yield-daddy/blob/main/src/aave-v3/AaveV3ERC4626.sol))

## Main invariants

The PrizeVault invariants are split into two categories:
1. Invariants for normal operating conditions
2. Invariants for when the underlying yield vault has lost funds (recovery mode)

### Normal Operating Conditions

- `totalAssets()` >= `totalDebt()`
- `totalDebt()` >= `totalSupply()`
- `liquidatableBalanceOf(...)` <= `availableYieldBalance()`
- `totalAssets()` == `(totalDebt() + currentYieldBuffer() + availableYieldBalance())` == `(totalDebt() + totalYieldBalance())`

### Yield Vault has Loss of Funds (recovery mode)

> The vault enters this state if the totalAssets is less than the totalDebt.

- no new deposits or mints allowed
- no liquidations can occur
- `availableYieldBalance()` == `0`
- `liquidatableBalanceOf(...)` == `0`
- `totalAssets()` == `convertToAssets(totalDebt())` (up to 1 unit rounding error acceptable)

## Scoping Details 

```
- If you have a public code repo, please share it here: https://github.com/GenerationSoftware/pt-v5-vault/tree/94b0c034c68b5318a25211a7b9f6d9ff6693e6ab
- How many contracts are in scope?: 6
- Total SLoC for these contracts?:  648
- How many external imports are there?: 2
- How many separate interfaces and struct definitions are there for the contracts within scope?:  7
- Does most of your code generally use composition or inheritance?:   Composition
- How many external calls?:   30
- What is the overall line coverage percentage provided by your tests?: 99%
- Is this an upgrade of an existing system?: True - This is a re-write of the Vault contract from PT V5
- Check all that apply (e.g. timelock, NFT, AMM, ERC20, rollups, etc.): ERC-20 Token
- Is there a need to understand a separate part of the codebase / get context in order to audit this part of the protocol?: False
- Please describe required context:   n/a
- Does it use an oracle?:  No
- Describe any novel or unique curve logic or mathematical models your code uses: None
- Is this either a fork of or an alternate implementation of another project?:  False
- Does it use a side-chain?:  No
- Describe any specific areas you would like addressed:  ERC4626 compliance and possible yield vault integration issues
```

# Tests

All the code relevant to the audit is included in the [pt-v5-vault](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/) folder in this repository. The following instructions will get you up and running with the development environment and tests.

### Clone the repo locally

Start by cloning this repo locally and navigate to the `pt-v5-vault` directory.

### Installation

You may have to install the following tools to use this repository:

- [Foundry](https://github.com/foundry-rs/foundry) to compile and test contracts
- [direnv](https://direnv.net/) to handle environment variables
- [lcov](https://github.com/linux-test-project/lcov) to generate the code coverage report

Install dependencies:

```
npm i
```

... then run:

```
forge install
```

### Env

Copy `.envrc.example` and write down the env variables needed to run this project. These include RPC URLs for fork tests.

```
cp .envrc.example .envrc
```

Once your env variables are setup, load them with:

```
direnv allow
```

### Compile

Run the following command to compile the contracts:

```
npm run compile
```

### Coverage

Forge is used for coverage, run it with:

```
npm run coverage
```

You can then consult the report by opening `coverage/index.html`:

```
open coverage/index.html
```

### Tests

You can run tests with the following commands:

- **unit tests:** `npm run test`
- **fuzz tests:** `npm run fuzz`
- **invariant tests:** `npm run invariant`
- **integration tests:** `npm run integration` (*informative for which integrations have potential issues*)


## Miscellaneous

Employees of [SPONSOR NAME] and employees' family members are ineligible to participate in this audit.
