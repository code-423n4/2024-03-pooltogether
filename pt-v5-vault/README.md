<p align="center">
  <a href="https://github.com/pooltogether/pooltogether--brand-assets">
    <img src="https://github.com/pooltogether/pooltogether--brand-assets/blob/977e03604c49c63314450b5d432fe57d34747c66/logo/pooltogether-logo--purple-gradient.png?raw=true" alt="PoolTogether Brand" style="max-width:100%;" width="400">
  </a>
</p>

# PoolTogether V5 Vault

[![Code Coverage](https://github.com/GenerationSoftware/pt-v5-vault/actions/workflows/coverage.yml/badge.svg)](https://github.com/GenerationSoftware/pt-v5-vault/actions/workflows/coverage.yml)
[![built-with openzeppelin](https://img.shields.io/badge/built%20with-OpenZeppelin-3677FF)](https://docs.openzeppelin.com/)
![MIT license](https://img.shields.io/badge/license-MIT-blue)

<strong>Have questions or want the latest news?</strong>
<br/>Join the PoolTogether Discord or follow us on Twitter:

[![Discord](https://badgen.net/badge/icon/discord?icon=discord&label)](https://pooltogether.com/discord)
[![Twitter](https://badgen.net/badge/icon/twitter?icon=twitter&label)](https://twitter.com/PoolTogether_)

## Overview

In PoolTogether V5 deposits are held in prize vaults. Prize vaults are [ERC4626](https://eips.ethereum.org/EIPS/eip-4626) compatible and are the entry point for users interacting with the PoolTogether protocol. Users deposit an underlying asset (i.e. USDC) in this contract which is then funnelled to a yield source and in exchange users receive an ERC20 token representing their share of deposits in the vault.

- Balances are stored in a TWAB Controller.
- Yield is forwarded to the Liquidator to be sold.

## Development

### Installation

You may have to install the following tools to use this repository:

- [Foundry](https://github.com/foundry-rs/foundry) to compile and test contracts
- [direnv](https://direnv.net/) to handle environment variables
- [lcov](https://github.com/linux-test-project/lcov) to generate the code coverage report

Install dependencies:

```
npm i
```

### Env

Copy `.envrc.example` and write down the env variables needed to run this project.

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
