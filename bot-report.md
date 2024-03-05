# Winning bot race submission
This is the top-ranked automated findings report, from Cygnet bot. All findings in this report will be considered known issues for the purposes of your C4 audit.

> Note: instance references are limited to a maximum ~99 to keep the report length reasonable

## Summary

| |Issue|Instances| Gas Savings
|-|:-|:-:|:-:|
| [[M-01](#m-01)] | Contracts are vulnerable to rebasing accounting-related issues | 2| 0|
| [[M-02](#m-02)] | ERC-20: 'transfer()'/'transferFrom()' return values should be checked | 2| 0|
| [[M-03](#m-03)] | ERC20: unsafe use of `transfer()`/`transferFrom()`  | 2| 0|
| [[M-04](#m-04)] | Return values of `approve()` not checked | 2| 0|
| [[L-01](#l-01)] | Arrays can grow in size without a way to shrink them | 1| 0|
| [[L-02](#l-02)] | Code does not follow the best practice of check-effects-interaction | 1| 0|
| [[L-03](#l-03)] | Consider disallowing minting/transfers to `address(this)` | 2| 0|
| [[L-04](#l-04)] | Consider implementing two-step procedure for updating protocol addresses | 5| 0|
| [[L-05](#l-05)] | ERC-20: Large transfers may revert | 3| 0|
| [[L-06](#l-06)] | Events may be emitted out of order due to reentrancy | 6| 0|
| [[L-07](#l-07)] | File allows a version of solidity that is susceptible to `.selector`-related optimizer bug | 1| 0|
| [[L-08](#l-08)] | Functions calling contracts/addresses with transfer hooks are missing reentrancy guards | 1| 0|
| [[L-09](#l-09)] | Missing checks for `address(0x0)` in the constructor/initializer | 3| 0|
| [[L-10](#l-10)] | Missing checks for `address(0x0)` when updating `address` state variables | 1| 0|
| [[L-11](#l-11)] | Missing checks for state variable assignments | 1| 0|
| [[L-12](#l-12)] | Owner can renounce Ownership | 1| 0|
| [[L-13](#l-13)] | Some tokens may revert when zero value transfers are made | 3| 0|
| [[L-14](#l-14)] | The `owner` is a single point of failure and a centralization risk | 4| 0|
| [[L-15](#l-15)] | Unsafe integer downcast | 1| 0|
| [[L-16](#l-16)] | Use `Ownable2Step` rather than `Ownable` | 1| 0|
| [[L-17](#l-17)] | Use `abi.encodeCall()` instead of `abi.encodeWithSignature()`/`abi.encodeWithSelector()` | 1| 0|
| [[L-18](#l-18)] | `approve()`/`safeApprove()` may revert if the current approval is not zero | 2| 0|
| [[L-19](#l-19)] | `unchecked` blocks with subtractions may underflow | 4| 0|
| [[G-01](#g-01)] | Assembly: Check `msg.sender` using `xor` and the scratch space | 4| 48|
| [[G-02](#g-02)] | Assembly: Checks for `address(0x0)` are more efficient in assembly | 7| 42|
| [[G-03](#g-03)] | Assembly: Use scratch space for building calldata | 30| 30|
| [[G-04](#g-04)] | Assembly: Use scratch space for calculating small `keccak256` hashes | 1| 80|
| [[G-05](#g-05)] | Assembly: Use scratch space when building emitted events with two data arguments | 2| 2|
| [[G-06](#g-06)] | Avoid updating storage when the value hasn't changed | 5| 4000|
| [[G-07](#g-07)] | Cache multiple accesses of mapping/array values | 4| 24|
| [[G-08](#g-08)] | Cache state variables accessed multiple times in the same function | 4| 388|
| [[G-09](#g-09)] | Consider changing some `public` variables to `private`/`internal` | 16| 0|
| [[G-10](#g-10)] | Consider pre-calculating the address of `address(this)` to save gas | 23| 805|
| [[G-11](#g-11)] | Constructors can be marked `payable` | 3| 63|
| [[G-12](#g-12)] | Detect zero value transfers to save gas | 2| 100|
| [[G-13](#g-13)] | Divisions can be `unchecked` to save gas | 1| 1|
| [[G-14](#g-14)] | Duplicated `require()`/`revert()` checks should be refactored to a modifier or function to save deployment gas | 1| 1|
| [[G-15](#g-15)] | Emitting constants wastes gas | 2| 16|
| [[G-16](#g-16)] | Enable IR-based code generation | 6| 0|
| [[G-17](#g-17)] | Function names can be optimized to save gas | 5| 110|
| [[G-18](#g-18)] | Functions guaranteed to revert when called by normal users can be marked `payable` | 8| 168|
| [[G-19](#g-19)] | Inline `internal` functions that are only called once | 2| 40|
| [[G-20](#g-20)] | Inline `modifier`s that are only used once, to save gas | 2| 100|
| [[G-21](#g-21)] | Mappings are cheaper to use than storage arrays | 1| 0|
| [[G-22](#g-22)] | Multiple accesses of a mapping/array should use a local variable cache | 4| 168|
| [[G-23](#g-23)] | Nesting `if`-statements is cheaper than using `&&` | 1| 6|
| [[G-24](#g-24)] | Only emit event in setter function if the state variable was changed | 5| 0|
| [[G-25](#g-25)] | Operator `>=`/`<=` costs less gas than operator `>`/`<` | 10| 30|
| [[G-26](#g-26)] | Public functions not used internally can be marked as external to save gas | 10| 410|
| [[G-27](#g-27)] | Reduce deployment gas costs by fine-tuning IPFS file hashes | 6| 0|
| [[G-28](#g-28)] | Reduce gas usage by moving to Solidity 0.8.19 or later | 1| 0|
| [[G-29](#g-29)] | Redundant state variable getters | 1| 0|
| [[G-30](#g-30)] | Redundant type conversion | 2| 80|
| [[G-31](#g-31)] | Refactor modifiers to call a local function | 3| 0|
| [[G-32](#g-32)] | Replace OpenZeppelin components with Solady equivalents to save gas | 3| 150|
| [[G-33](#g-33)] | Same cast is done multiple times | 6| 30|
| [[G-34](#g-34)] | Simple checks for zero can be done using assembly to save gas | 8| 48|
| [[G-35](#g-35)] | Split `revert` checks to save gas | 1| 2|
| [[G-36](#g-36)] | Stack variable is only used once | 45| 180|
| [[G-37](#g-37)] | Subtraction can potentially be marked `unchecked` to save gas | 8| 80|
| [[G-38](#g-38)] | The result of function calls should be cached rather than re-calling the function | 4| 28|
| [[G-39](#g-39)] | Usage of non-`uint256`/`int256` types uses more gas | 22| 1166|
| [[G-40](#g-40)] | Use != 0 instead of > 0 | 1| 3|
| [[G-41](#g-41)] | Use Solady library where possible to save gas | 2| 2|
| [[G-42](#g-42)] | Use `calldata` instead of `memory` for function arguments that are read only | 6| 300|
| [[G-43](#g-43)] | Use `private` rather than `public` for constants | 4| 0|
| [[G-44](#g-44)] | Use `uint256(1)`/`uint256(2)` instead of `true`/`false` to save gas for changes | 1| 8550|
| [[G-45](#g-45)] | Use assembly to calculate hashes | 1| 80|
| [[G-46](#g-46)] | Use assembly to perform external calls, in order to save gas | 13| 260|
| [[G-47](#g-47)] | Use assembly to write storage values | 14| 154|
| [[G-48](#g-48)] | Use more recent OpenZeppelin version for gas boost | 8| 0|
| [[G-49](#g-49)] | Use named `return` parameters | 40| 520|
| [[G-50](#g-50)] | Use nested `if`s instead of `&&` | 1| 15|
| [[G-51](#g-51)] | Using `bool`s for storage incurs overhead | 1| 100|
| [[G-52](#g-52)] | `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) | 1| 5|
| [[G-53](#g-53)] | `<x> += <y>` costs more gas than `<x> = <x> + <y>` for state variables | 2| 226|
| [[G-54](#g-54)] | `abi.encode()` is less efficient than `abi.encodepacked()` for non-address arguments | 1| 100|
| [[N-01](#n-01)] | Add inline comments for unnamed variables | 4| 0|
| [[N-02](#n-02)] | Complex arithmetic expression | 1| 0|
| [[N-03](#n-03)] | Consider adding a block/deny-list | 3| 0|
| [[N-04](#n-04)] | Consider adding emergency-stop functionality | 2| 0|
| [[N-05](#n-05)] | Consider adding formal verification proofs | 6| 0|
| [[N-06](#n-06)] | Consider adding validation of user inputs | 26| 0|
| [[N-07](#n-07)] | Consider disabling `renounceOwnership()` | 1| 0|
| [[N-08](#n-08)] | Consider emitting an event from `constructor`s | 3| 0|
| [[N-09](#n-09)] | Consider making contracts `Upgradeable` | 2| 0|
| [[N-10](#n-10)] | Consider moving `msg.sender` checks to `modifier`s | 4| 0|
| [[N-11](#n-11)] | Consider providing a ranged getter for array state variables | 1| 0|
| [[N-12](#n-12)] | Consider splitting complex checks into multiple steps | 1| 0|
| [[N-13](#n-13)] | Consider upgrading OpenZeppelin dependency to a newer version | 8| 0|
| [[N-14](#n-14)] | Consider using descriptive `constant`s when passing zero as a function argument | 1| 0|
| [[N-15](#n-15)] | Consider using named function arguments | 12| 0|
| [[N-16](#n-16)] | Consider using named mappings | 1| 0|
| [[N-17](#n-17)] | Consider using the `using`-`for` syntax | 3| 0|
| [[N-18](#n-18)] | Constructor / initialization function lacks parameter validation | 1| 0|
| [[N-19](#n-19)] | Contract order does not follow Solidity style guide recommendations | 2| 0|
| [[N-20](#n-20)] | Contract should expose an `interface` | 3| 0|
| [[N-21](#n-21)] | Contracts and libraries should use fixed compiler versions | 5| 0|
| [[N-22](#n-22)] | Contracts should have full test coverage | 6| 0|
| [[N-23](#n-23)] | Critical system parameter changes should be behind a timelock | 4| 0|
| [[N-24](#n-24)] | Custom error has no error details | 14| 0|
| [[N-25](#n-25)] | Duplicate `require()`/`revert()` checks should be refactored to a modifier or function | 1| 0|
| [[N-26](#n-26)] | Events are missing sender information | 11| 0|
| [[N-27](#n-27)] | Events that mark critical parameter changes should contain both the old and the new value | 5| 0|
| [[N-28](#n-28)] | Function ordering does not follow the Solidity style guide | 4| 0|
| [[N-29](#n-29)] | High cyclomatic complexity | 1| 0|
| [[N-30](#n-30)] | Imports should be organized more systematically | 2| 0|
| [[N-31](#n-31)] | Large multiples of ten should use scientific notation for readability | 1| 0|
| [[N-32](#n-32)] | Large or complicated code bases should implement invariant tests | 6| 0|
| [[N-33](#n-33)] | Naming: name immutables using all-uppercase | 6| 0|
| [[N-34](#n-34)] | NatSpec: Contract declarations should have `@dev` tags | 4| 0|
| [[N-35](#n-35)] | NatSpec: Error definitions should have `@dev` tags | 24| 0|
| [[N-36](#n-36)] | NatSpec: Event definitions should have `@dev` tags | 7| 0|
| [[N-37](#n-37)] | NatSpec: Function `@param` is missing | 1| 0|
| [[N-38](#n-38)] | NatSpec: Function definitions should have `@dev` tags | 29| 0|
| [[N-39](#n-39)] | NatSpec: Function definitions should have `@notice` tags | 25| 0|
| [[N-40](#n-40)] | NatSpec: Modifier definitions should have `@dev` tags | 3| 0|
| [[N-41](#n-41)] | NatSpec: Non-public state variable declarations should use `@dev` tags | 3| 0|
| [[N-42](#n-42)] | NatSpec: missing from file | 6| 0|
| [[N-43](#n-43)] | Parameter change does not emit event | 3| 0|
| [[N-44](#n-44)] | Redundant `else` block | 7| 0|
| [[N-45](#n-45)] | Setters should prevent re-setting the same value | 5| 0|
| [[N-46](#n-46)] | Style guide: Non-`external`/`public` function names should begin with an underscore | 1| 0|
| [[N-47](#n-47)] | Style guide: State and local variables should be named using lowerCamelCase | 45| 0|
| [[N-48](#n-48)] | Style guide: Using underscore at the end of variable name | 26| 0|
| [[N-49](#n-49)] | Style: surround top level declarations with two blank lines | 5| 0|
| [[N-50](#n-50)] | Syntax: place constants on left-hand side of comparisons | 9| 0|
| [[N-51](#n-51)] | Syntax: unnecessary `override` | 6| 0|
| [[N-52](#n-52)] | Unnecessary cast | 2| 0|
| [[N-53](#n-53)] | Unused `error` definition | 1| 0|
| [[N-54](#n-54)] | Unused `function` definition | 3| 0|
| [[N-55](#n-55)] | Unused `struct` definition | 1| 0|
| [[N-56](#n-56)] | Unused import | 1| 0|
| [[N-57](#n-57)] | Use a single file for system wide constants | 4| 0|
| [[N-58](#n-58)] | Use a struct to encapsulate multiple function parameters | 7| 0|
| [[N-59](#n-59)] | Use safePermit in place of permit | 1| 0|
| [[N-60](#n-60)] | Use ternary expressions over `if`/`else` where possible | 5| 0|
| [[N-61](#n-61)] | Use the latest Solidity version for deployment | 1| 0|
| [[N-62](#n-62)] | `constant`s should be defined rather than using magic numbers | 2| 0|
| [[N-63](#n-63)] | `public` functions not called by the contract should be declared `external` instead | 10| 0|
| [[D-01](#d-01)] | All `verbatim` blocks are considered identical by deduplicator and can incorrectly be unified | 6| 0|
| [[D-02](#d-02)] | Complex casting | 1| 0|
| [[D-03](#d-03)] | Consider using SMTChecker | 6| 0|
| [[D-04](#d-04)] | Consider using named function arguments | 39| 0|
| [[D-05](#d-05)] | Consider using solady's "FixedPointMathLib" | 2| 0|
| [[D-06](#d-06)] | Contracts and libraries should use fixed compiler versions | 1| 0|
| [[D-07](#d-07)] | Contracts are vulnerable to fee-on-transfer accounting-related issues | 2| 0|
| [[D-08](#d-08)] | Floating pragma should be avoided | 5| 0|
| [[D-09](#d-09)] | Lack of two-step update for critical functions | 3| 0|
| [[D-10](#d-10)] | Natspec comments are missing from scope blocks | 41| 0|
| [[D-11](#d-11)] | Natspec is missing from struct | 1| 0|
| [[D-12](#d-12)] | Optimize Gas by Splitting if() revert Statements | 1| 0|
| [[D-13](#d-13)] | Revert statements within external and public functions can be used to perform DOS attacks | 13| 0|
| [[D-14](#d-14)] | Solidity version 0.8.20 may not work on other chains due to `PUSH0` | 1| 0|
| [[D-15](#d-15)] | Structs can be packed into fewer storage slots | 1| 2000|
| [[D-16](#d-16)] | Structs can be packed into fewer storage slots by truncating timestamp bytes | 1| 2000|
| [[D-17](#d-17)] | Trade-offs Between Modifiers and Internal Functions | 19| 0|
| [[D-18](#d-18)] | Upgradeable contract uses non-upgradeable version of the OpenZeppelin libraries/contracts | 8| 0|
| [[D-19](#d-19)] | Use Unchecked for Divisions on Constant or Immutable Values | 1| 0|
| [[D-20](#d-20)] | Use assembly to perform external calls, in order to save gas | 86| 1720|
| [[D-21](#d-21)] | Use bitmap to save gas | 1| 0|

### Medium Risk Issues

### [M-01]<a name="m-01"></a> Contracts are vulnerable to rebasing accounting-related issues

> The readme **does not** specifically exclude rebasing tokens

Rebasing tokens are tokens that have each holder's `balanceof()` increase over time. Aave aTokens are an example of such tokens. If rebasing tokens are used, rewards accrue to the contract holding the tokens, and cannot be withdrawn by the original depositor. To address the issue, track 'shares' deposited on a pro-rata basis, and let shares be redeemed for their proportion of the current balance at the time of the withdrawal.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Ensure shares are tracked for rebasing tokens
 854 |  _asset.safeTransferFrom(
 855 |      _caller,
 856 |      address(this),
 857 |      _assets
 858 |  );
```

*GitHub* : [854-858](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L854-L858)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Ensure shares are tracked for rebasing tokens
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118)

### [M-02]<a name="m-02"></a> ERC-20: 'transfer()'/'transferFrom()' return values should be checked

Not all `IERC20` implementations `revert()` when there's a failure in `transfer()`/`transferFrom()`. The function signature has a `boolean` return value and they indicate errors that way [instead](https://etherscan.io/address/0x25d772b21b0e5197f2dc8169e3aa976b16be04ac#code#F1#L44). By not checking the return value, operations that should have marked as failed, may potentially go through without actually making a payment

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Check return value
 939 |  _asset.transfer(_receiver, _assets);
```

*GitHub* : [939](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L939)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Check return value
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118)

### [M-03]<a name="m-03"></a> ERC20: unsafe use of `transfer()`/`transferFrom()` 

Some tokens do not implement the ERC20 standard properly but are still accepted by most code that accepts ERC20 tokens.  For example Tether (USDT)'s `transfer()` and `transferFrom()` functions on L1 do not return booleans as the specification requires, and instead have no return value. When these sorts of tokens are cast to `IERC20`, their [function signatures](https://medium.com/coinmonks/missing-return-value-bug-at-least-130-tokens-affected-d67bf08521ca) do not match and therefore the calls made, revert (see [this](https://gist.github.com/IllIllI000/2b00a32e8f0559e8f386ea4f1800abc5) link for a test case). Use OpenZeppelin’s `SafeERC20`'s `safeTransfer()`/`safeTransferFrom()` instead

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Use safeTransfer()/safeTransferFrom()
 939 |  _asset.transfer(_receiver, _assets);
```

*GitHub* : [939](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L939)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Use safeTransfer()/safeTransferFrom()
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118)

### [M-04]<a name="m-04"></a> Return values of `approve()` not checked

Not all `IERC20` implementations `revert()` when there's a failure in `approve()`. The function signature has a `boolean` return value and they indicate errors that way instead. By not checking the return value, operations that should have marked as failed, may potentially go through without actually approving anything.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Check approve() return value
 862 |  _asset.approve(address(yieldVault), _assetsWithDust);

     |  // @audit-issue Check approve() return value
 869 |  _asset.approve(address(yieldVault), 0);
```

*GitHub* : [862](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L862), [869](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L869)

### Low Risk Issues

### [L-01]<a name="l-01"></a> Arrays can grow in size without a way to shrink them

Array entries are added but are never removed. Consider whether this should be the case, or whether there should be a maximum, or whether old entries should be removed. Cases where there are specific potential problems will be flagged separately under a different issue.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue No corresponding `pop()` for this `push()`
 120 |  allVaults.push(_vault);
```

*GitHub* : [120](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L120)

### [L-02]<a name="l-02"></a> Code does not follow the best practice of check-effects-interaction

Code should follow the best-practice of [check-effects-interaction](https://blockchain-academy.hs-mittweida.de/courses/solidity-coding-beginners-to-intermediate/lessons/solidity-11-coding-patterns/topic/checks-effects-interactions/), where state variables are updated before any external calls are made. Doing so prevents a large class of reentrancy bugs.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-info External call
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
  :  |
     |  // @audit-issue State variable assignment after external call
 121 |  deployedVaults[address(_vault)] = true;
```

*GitHub* : [121](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L121)

### [L-03]<a name="l-03"></a> Consider disallowing minting/transfers to `address(this)`

A tranfer to the token contract itself is unlikely to be correct and more likely to be a common user error due to a copy & paste mistake. Proceeding with such a transfer will result in the permanent loss of user tokens.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Check receiver isn't `address(this)`
 482 |  function mint(uint256 _shares, address _receiver) external returns (uint256) {
 483 |      uint256 _assets = previewMint(_shares);
 484 |      _depositAndMint(msg.sender, _receiver, _assets, _shares);
 485 |      return _assets;
 486 |  }
```

*GitHub* : [482-486](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L482-L486)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Check receiver isn't `address(this)`
  76 |  function _mint(address _receiver, uint256 _amount) internal virtual override {
  77 |      twabController.mint(_receiver, SafeCast.toUint96(_amount));
  78 |      emit Transfer(address(0), _receiver, _amount);
  79 |  }
```

*GitHub* : [76-79](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L76-L79)

### [L-04]<a name="l-04"></a> Consider implementing two-step procedure for updating protocol addresses

A copy-paste error or a typo may end up bricking protocol functionality, or sending tokens to an address with no known private key. Consider implementing a two-step procedure for updating protocol addresses, where the recipient is set as pending, and must 'accept' the assignment by making an affirmative call. A straight forward way of doing this would be to have the target contracts implement [EIP-165](https://eips.ethereum.org/EIPS/eip-165), and to have the 'set' functions ensure that the recipient is of the right interface type.
                    
Note: this is different for **non-**`address` parameters, where the recommendation is to use a timelock.

*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider implementing two-step verification of the new value
 735 |  function setClaimer(address _claimer) external onlyOwner {

     |  // @audit-issue Consider implementing two-step verification of the new value
 742 |  function setLiquidationPair(address _liquidationPair) external onlyOwner {

     |  // @audit-issue Consider implementing two-step verification of the new value
 759 |  function setYieldFeeRecipient(address _yieldFeeRecipient) external onlyOwner {

     |  // @audit-issue Consider implementing two-step verification of the new value
 958 |  function _setYieldFeeRecipient(address _yieldFeeRecipient) internal {
```

*GitHub* : [735](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L735), [742](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L742), [759](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L759), [958](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L958)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider implementing two-step verification of the new value
 128 |  function _setClaimer(address _claimer) internal {
```

*GitHub* : [128](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L128)

### [L-05]<a name="l-05"></a> ERC-20: Large transfers may revert

Some `IERC20` implementations (e.g `UNI`, `COMP`) may fail if the valued `transferred` is larger than `uint96`. [Source](https://github.com/d-xo/weird-erc20/blob/main/src/Uint96.sol).

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Check balance before & after vs. expected
 854 |  _asset.safeTransferFrom(
 855 |      _caller,
 856 |      address(this),
 857 |      _assets
 858 |  );

     |  // @audit-issue Check balance before & after vs. expected
 939 |  _asset.transfer(_receiver, _assets);
```

*GitHub* : [854-858](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L854-L858), [939](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L939)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Check balance before & after vs. expected
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118)

### [L-06]<a name="l-06"></a> Events may be emitted out of order due to reentrancy

To strictly conform to the Checks Effects Interactions pattern, it is recommended to emit events before any external interactions.

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |      // @audit-info External call
 559 |      twabController.sponsor(_owner);
  :  |
     |  // @audit-issue Event emitted after external call
 562 |  emit Sponsor(_owner, _assets, _shares);

     |  // @audit-info External call
 854 |  _asset.safeTransferFrom(
 855 |      _caller,
 856 |      address(this),
 857 |      _assets
 858 |  );
  :  |
     |  // @audit-info External call
 862 |  _asset.approve(address(yieldVault), _assetsWithDust);
  :  |
     |      // @audit-info External call
 869 |      _asset.approve(address(yieldVault), 0);
  :  |
     |  // @audit-issue Event emitted after external call
 876 |  emit Deposit(_caller, _receiver, _assets, _shares);
```

*GitHub* : [562](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L562), [876](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L876)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-info External call
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
  :  |
     |  // @audit-issue Event emitted after external call
 123 |  emit NewPrizeVault(
 124 |      _vault,
 125 |      _yieldVault,
 126 |      _prizePool,
 127 |      _name,
 128 |      _symbol
 129 |  );
```

*GitHub* : [123-129](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L123-L129)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-info External call
  77 |  twabController.mint(_receiver, SafeCast.toUint96(_amount));
     |  // @audit-issue Event emitted after external call
  78 |  emit Transfer(address(0), _receiver, _amount);

     |  // @audit-info External call
  88 |  twabController.burn(_owner, SafeCast.toUint96(_amount));
     |  // @audit-issue Event emitted after external call
  89 |  emit Transfer(_owner, address(0), _amount);

     |  // @audit-info External call
 101 |  twabController.transfer(_from, _to, SafeCast.toUint96(_amount));
     |  // @audit-issue Event emitted after external call
 102 |  emit Transfer(_from, _to, _amount);
```

*GitHub* : [78](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L78), [89](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L89), [102](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L102)

### [L-07]<a name="l-07"></a> File allows a version of solidity that is susceptible to `.selector`-related optimizer bug

In solidity versions prior to 0.8.21, there is a legacy code generation [bug](https://soliditylang.org/blog/2023/07/19/missing-side-effects-on-selector-access-bug/) where if `foo().selector` is called, `foo()` doesn't actually get evaluated. It is listed as low-severity, because projects usually use the contract name rather than a function call to look up the selector. I've flagged all files using `.selector` where the version is vulnerable.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

   2 |  pragma solidity ^0.8.0;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L2)

### [L-08]<a name="l-08"></a> Functions calling contracts/addresses with transfer hooks are missing reentrancy guards

Even if the function follows the best practice of check-effects-interaction, not using a reentrancy guard when there may be transfer hooks will open the users of this protocol up to [read-only reentrancies](https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/) with no way to protect against it, except by block-listing the whole protocol.

> Note: the instances below may show multiple paths, via other functions, to the same `transfer` to ensure all paths have been considered

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info No re-entrancy guard
 659 |  function transferTokensOut(
 660 |      address,
 661 |      address _receiver,
 662 |      address _tokenOut,
 663 |      uint256 _amountOut
 664 |  ) public virtual onlyLiquidationPair returns (bytes memory) {
  :  |
     |          // @audit-issue Add re-entrancy guard to protect against transfer hook manipulation
 939 |          _asset.transfer(_receiver, _assets);
```

*GitHub* : [939](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L939)

### [L-09]<a name="l-09"></a> Missing checks for `address(0x0)` in the constructor/initializer

Since `address(0x0)` has no private key, it is almost always a mistake when used outside of burning operations, and would result in losing deployment due to the need for redeployment.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue yieldVault_
 289 |  constructor(
 290 |      string memory name_,
 291 |      string memory symbol_,
 292 |      IERC4626 yieldVault_,
 293 |      PrizePool prizePool_,
 294 |      address claimer_,
 295 |      address yieldFeeRecipient_,
 296 |      uint32 yieldFeePercentage_,
 297 |      uint256 yieldBuffer_,
 298 |      address owner_
 299 |  ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {
```

*GitHub* : [289-299](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L289-L299)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue twabController_
  42 |  constructor(
  43 |      string memory name_,
  44 |      string memory symbol_,
  45 |      TwabController twabController_
  46 |  ) ERC20(name_, symbol_) ERC20Permit(name_) {
```

*GitHub* : [42-46](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L42-L46)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue prizePool_
  64 |  constructor(PrizePool prizePool_, address claimer_) {
```

*GitHub* : [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L64)

### [L-10]<a name="l-10"></a> Missing checks for `address(0x0)` when updating `address` state variables

Since `address(0x0)` has no private key, it is almost always a mistake when used outside of burning operations.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Verify `_yieldFeeRecipient` != address(0)
 958 |  function _setYieldFeeRecipient(address _yieldFeeRecipient) internal {
```

*GitHub* : [958](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L958)

### [L-11]<a name="l-11"></a> Missing checks for state variable assignments

There are some missing checks in these functions, and this could lead to unexpected scenarios. Consider always adding a sanity check for state variables.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue `_yieldFeeRecipient` is assigned to a state variable, unvalidated
 958 |  function _setYieldFeeRecipient(address _yieldFeeRecipient) internal {
```

*GitHub* : [958](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L958)

### [L-12]<a name="l-12"></a> Owner can renounce Ownership

Each of the following contracts implements or inherits the `renounceOwnership()` function. This can represent a certain risk if the ownership is renounced for any other reason than by design. Renouncing ownership will leave the contract without an owner, thereby removing any functionality that is only available to the owner.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider whether `renounceOwnership` is required
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
```

*GitHub* : [65](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L65)

### [L-13]<a name="l-13"></a> Some tokens may revert when zero value transfers are made

In spite of the fact that EIP-20 [states](https://github.com/ethereum/EIPs/blob/46b9b698815abbfa628cd1097311deee77dd45c5/EIPS/eip-20.md?plain=1#L116) that zero-valued transfers must be accepted, some tokens, such as LEND will revert if this is attempted, which may cause transactions that involve other tokens (such as batch operations) to fully revert. Consider skipping the transfer if the amount is zero, which will also save gas.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Check transfer amount > 0
 854 |  _asset.safeTransferFrom(
 855 |      _caller,
 856 |      address(this),
 857 |      _assets
 858 |  );

     |  // @audit-issue Check transfer amount > 0
 939 |  _asset.transfer(_receiver, _assets);
```

*GitHub* : [854-858](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L854-L858), [939](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L939)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Check transfer amount > 0
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118)

### [L-14]<a name="l-14"></a> The `owner` is a single point of failure and a centralization risk

Having a single EOA as the only owner of contracts is a large centralization risk and a single point of failure. A single private key may be taken in a hack, or the sole holder of the key may become unable to retrieve the key when necessary, or the single owner can become malicious and perform a rug-pull. Consider changing to a multi-signature setup, and or having a role-based authorization model.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider more granular roles to limit centralization risks
 735 |  function setClaimer(address _claimer) external onlyOwner {

     |  // @audit-issue Consider more granular roles to limit centralization risks
 742 |  function setLiquidationPair(address _liquidationPair) external onlyOwner {

     |  // @audit-issue Consider more granular roles to limit centralization risks
 753 |  function setYieldFeePercentage(uint32 _yieldFeePercentage) external onlyOwner {

     |  // @audit-issue Consider more granular roles to limit centralization risks
 759 |  function setYieldFeeRecipient(address _yieldFeeRecipient) external onlyOwner {
```

*GitHub* : [735](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L735), [742](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L742), [753](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L753), [759](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L759)

### [L-15]<a name="l-15"></a> Unsafe integer downcast

When a type is downcast to a smaller type, the higher order bits are truncated, effectively applying a modulo to the original value. Without any other checks, this wrapping will lead to unexpected behavior and bugs.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Casting from uint256 to uint8 will truncate bits
 779 |  return (true, uint8(returnedDecimals));
```

*GitHub* : [779](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L779)

### [L-16]<a name="l-16"></a> Use `Ownable2Step` rather than `Ownable`

[`Ownable2Step`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/3d7a93876a2e5e1d7fe29b5a0e96e222afdc4cfa/contracts/access/Ownable2Step.sol#L31-L56) and [`Ownable2StepUpgradeable`](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/25aabd286e002a1526c345c8db259d57bdf0ad28/contracts/access/Ownable2StepUpgradeable.sol#L47-L63) prevent the contract ownership from mistakenly being transferred to an address that cannot handle it (e.g. due to a typo in the address), by requiring that the recipient of the owner permissions actively accept via a contract call of its own.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider Ownable2Step instead of Ownable
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
```

*GitHub* : [65](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L65)

### [L-17]<a name="l-17"></a> Use `abi.encodeCall()` instead of `abi.encodeWithSignature()`/`abi.encodeWithSelector()`

`abi.encodeCall()` has compiler [type safety](https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3693), whereas the other two functions do not

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider abi.encodeCall
 774 |  abi.encodeWithSelector(IERC20Metadata.decimals.selector)
```

*GitHub* : [774](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L774)

### [L-18]<a name="l-18"></a> `approve()`/`safeApprove()` may revert if the current approval is not zero

Calling `approve()` without first calling `approve(0)` if the current approval is non-zero will revert with some tokens, such as Tether (USDT). While Tether is known to do this, it applies to other tokens as well, which are trying to protect against [this attack vector](https://docs.google.com/document/d/1YLPtQxZu1UAvO9cZ1O2RPXBbT0mooh4DYKjA_jp-RLM/edit). `safeApprove()` itself also implements this protection.

Always reset the approval to zero before changing it to a new value (OpenZeppelin's `SafeERC20.forceApprove()` does this for you), or use `safeIncreaseAllowance()`/`safeDecreaseAllowance()`

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Call approve(0) first
 862 |  _asset.approve(address(yieldVault), _assetsWithDust);

     |  // @audit-issue Call approve(0) first
 869 |  _asset.approve(address(yieldVault), 0);
```

*GitHub* : [862](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L862), [869](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L869)

### [L-19]<a name="l-19"></a> `unchecked` blocks with subtractions may underflow

There aren't any checks to avoid an underflow which can happen inside an `unchecked` block, so the following subtractions may underflow silently.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info This unchecked block has risks
 387 |  unchecked {
     |      // @audit-issue This unchecked arithmetic operation is unsafe
 388 |      _maxDeposit = _maxYieldVaultDeposit - _latentBalance;

     |  // @audit-info This unchecked block has risks
 799 |  unchecked {
     |      // @audit-issue This unchecked arithmetic operation is unsafe
 800 |      return type(uint96).max - _totalSupply;

     |  // @audit-info This unchecked block has risks
 812 |  unchecked {
     |      // @audit-issue This unchecked arithmetic operation is unsafe
 813 |      return _totalAssets - totalDebt_;

     |  // @audit-info This unchecked block has risks
 827 |  unchecked {
     |      // @audit-issue This unchecked arithmetic operation is unsafe
 828 |      return totalYieldBalance_ - _yieldBuffer;
```

*GitHub* : [388](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L388), [800](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L800), [813](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L813), [828](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L828)

### Gas Risk Issues

### [G-01]<a name="g-01"></a> Assembly: Check `msg.sender` using `xor` and the scratch space

We can use assembly to efficiently validate `msg.sender` with the least amount of opcodes necessary. For more details check the following report [here](https://code4rena.com/reports/2023-05-juicebox#g-06-use-assembly-to-validate-msgsender).

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 261 |  if (msg.sender != liquidationPair) {

 269 |  if (msg.sender != yieldFeeRecipient) {

 532 |  if (_owner != msg.sender) {
```

*GitHub* : [261](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L261), [269](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L269), [532](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L532)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

  53 |  if (msg.sender != claimer) revert CallerNotClaimer(msg.sender, claimer);
```

*GitHub* : [53](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L53)

### [G-02]<a name="g-02"></a> Assembly: Checks for `address(0x0)` are more efficient in assembly

Using assembly to check for zero can save gas by allowing more direct access to the evm and reducing some of the overhead associated with high-level operations in solidity.

*There are 7 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Use assembly zero check
 458 |  if (_totalAssets == 0) revert ZeroTotalAssets();

     |  // @audit-issue Use assembly zero check
 612 |  if (_shares == 0) revert MintZeroShares();

     |  // @audit-issue Use assembly zero check
 665 |  if (_amountOut == 0) revert LiquidationAmountOutZero();

     |  // @audit-issue Use assembly zero check
 844 |  if (_shares == 0) revert MintZeroShares();

     |  // @audit-issue Use assembly zero check
 845 |  if (_assets == 0) revert DepositZeroAssets();

     |  // @audit-issue Use assembly zero check
 894 |  if (_assets == 0) revert WithdrawZeroAssets();

     |  // @audit-issue Use assembly zero check
 895 |  if (_shares == 0) revert BurnZeroShares();
```

*GitHub* : [458](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L458), [612](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L612), [665](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L665), [844](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L844), [845](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L845), [894](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L894), [895](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L895)

### [G-03]<a name="g-03"></a> Assembly: Use scratch space for building calldata

If an external call's calldata can fit into two or fewer words, use the scratch space to build the calldata, rather than allowing Solidity to do a memory expansion.

*There are 30 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 299 |  ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {

 303 |  IERC20 asset_ = IERC20(yieldVault_.asset());

 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

 382 |  uint256 _latentBalance = _asset.balanceOf(address(this));

 383 |  uint256 _maxYieldVaultDeposit = yieldVault.maxDeposit(address(this));

 405 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

 416 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

 539 |  if (_asset.allowance(_owner, address(this)) != _assets) {

 558 |  if (twabController.delegateOf(address(this), _owner) != SPONSORSHIP_ADDRESS) {

 559 |  twabController.sponsor(_owner);

 639 |  _maxAmountOut = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

 708 |  address _prizeToken = address(prizePool.prizeToken());

 713 |  prizePool.contributePrizeTokens(address(this), _amountIn);

 861 |  uint256 _assetsWithDust = _asset.balanceOf(address(this));

 862 |  _asset.approve(address(yieldVault), _assetsWithDust);

 865 |  uint256 _yieldVaultShares = yieldVault.previewDeposit(_assetsWithDust);

 866 |  uint256 _assetsUsed = yieldVault.mint(_yieldVaultShares, address(this));

 869 |  _asset.approve(address(yieldVault), 0);

 922 |  return yieldVault.convertToAssets(yieldVault.maxRedeem(address(this)));

 922 |  return yieldVault.convertToAssets(yieldVault.maxRedeem(address(this)));

 931 |  uint256 _latentAssets = _asset.balanceOf(address(this));

 934 |  uint256 _yieldVaultShares = yieldVault.previewWithdraw(_assets - _latentAssets);

 939 |  _asset.transfer(_receiver, _assets);
```

*GitHub* : [299](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L299), [303](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L303), [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [382](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L382), [383](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L383), [405](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L405), [416](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L416), [539](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L539), [558](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L558), [559](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L559), [639](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L639), [708](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L708), [713](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L713), [861](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L861), [862](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L862), [865](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L865), [866](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L866), [869](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L869), [922](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L922), [922](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L922), [931](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L931), [934](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L934), [939](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L939)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

  59 |  return twabController.balanceOf(address(this), _account);

  64 |  return twabController.totalSupply(address(this));

  77 |  twabController.mint(_receiver, SafeCast.toUint96(_amount));

  88 |  twabController.burn(_owner, SafeCast.toUint96(_amount));
```

*GitHub* : [59](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L59), [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L64), [77](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L77), [88](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L88)

### [G-04]<a name="g-04"></a> Assembly: Use scratch space for calculating small `keccak256` hashes

If the arguments to the encode call can fit into the scratch space (two words or fewer), then it's more efficient to use assembly to generate the hash (**80 gas**):
`keccak256(abi.encodePacked(x, y))` -> `assembly {mstore(0x00, a); mstore(0x20, b); let hash := keccak256(0x00, 0x40); }`

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

 103 |  salt: keccak256(abi.encode(msg.sender, deployerNonces[msg.sender]++))
```

*GitHub* : [103](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L103)

### [G-05]<a name="g-05"></a> Assembly: Use scratch space when building emitted events with two data arguments

To efficiently emit events, it's possible to utilize assembly by making use of scratch space and the free memory pointer. This approach has the advantage of potentially avoiding the costs associated with memory expansion.

However, it's important to note that in order to safely optimize this process, it is preferable to cache and restore the free memory pointer.

A good example of such practice can be seen in [Solady's](https://github.com/Vectorized/solady/blob/main/src/tokens/ERC1155.sol#L167) codebase.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 621 |  emit ClaimYieldFeeShares(msg.sender, _shares);

 747 |  emit LiquidationPairSet(address(this), address(_liquidationPair));
```

*GitHub* : [621](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L621), [747](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L747)

### [G-06]<a name="g-06"></a> Avoid updating storage when the value hasn't changed

If the old value is equal to the new value, not re-storing the value will avoid a `Gsreset` (2900 gas), potentially at the expense of a `Gcoldsload` (2100 gas) or a `Gwarmaccess` (100 gas). Min = `Gsreset` - `Gcoldsload`, Max = `Gsreset` - `Gwarmaccess`.

*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Contains state variable assignments
 742 |  function setLiquidationPair(address _liquidationPair) external onlyOwner {
  :  |
     |      // @audit-issue Consider checking if the value has changed first
 745 |      liquidationPair = _liquidationPair;

     |  // @audit-info Contains state variable assignments
 947 |  function _setYieldFeePercentage(uint32 _yieldFeePercentage) internal {
  :  |
     |      // @audit-issue Consider checking if the value has changed first
 951 |      yieldFeePercentage = _yieldFeePercentage;

     |  // @audit-info Contains state variable assignments
 958 |  function _setYieldFeeRecipient(address _yieldFeeRecipient) internal {
     |      // @audit-issue Consider checking if the value has changed first
 959 |      yieldFeeRecipient = _yieldFeeRecipient;
```

*GitHub* : [745](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L745), [951](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L951), [959](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L959)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-info Contains state variable assignments
 128 |  function _setClaimer(address _claimer) internal {
  :  |
     |      // @audit-issue Consider checking if the value has changed first
 130 |      claimer = _claimer;
```

*GitHub* : [130](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L130)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-info Contains state variable assignments
  29 |  function setHooks(VaultHooks calldata hooks) external {
     |      // @audit-issue Consider checking if the value has changed first
  30 |      _hooks[msg.sender] = hooks;
```

*GitHub* : [30](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L30)

### [G-07]<a name="g-07"></a> Cache multiple accesses of mapping/array values

Caching a mapping's value in a local `storage` or `calldata` variable when the value is accessed multiple times, saves ~42 gas per access due to not having to recalculate the key's keccak256 hash (Gkeccak256 - 30 gas) and that calculation's associated stack operations. Caching an array's struct avoids recalculating the array offsets into memory/calldata.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-info Contains multiple accesses to state
  76 |  function claimPrize(
  77 |      address _winner,
  78 |      uint8 _tier,
  79 |      uint32 _prizeIndex,
  80 |      uint96 _reward,
  81 |      address _rewardRecipient
  82 |  ) external onlyClaimer returns (uint256) {
  :  |
     |      // @audit-issue Cache this value
  85 |      if (_hooks[_winner].useBeforeClaimPrize) {
     |          // @audit-issue Cache this value
  86 |          recipient = _hooks[_winner].implementation.beforeClaimPrize{ gas: HOOK_GAS }(
  :  |
     |      // @audit-issue Cache this value
 108 |      if (_hooks[_winner].useAfterClaimPrize) {
     |          // @audit-issue Cache this value
 109 |          _hooks[_winner].implementation.afterClaimPrize{ gas: HOOK_GAS }(
```

*GitHub* : [85](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L85), [86](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L86), [108](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L108), [109](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L109)

### [G-08]<a name="g-08"></a> Cache state variables accessed multiple times in the same function

The instances below point to the second+ access of a state variable within a function. Caching of a state variable replaces each Gwarmaccess (100 gas) with a much cheaper stack read. Other less obvious fixes/optimizations include having local memory caches of state variable structs, or having local caches of state variable contracts/addresses.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

  76 |  function claimPrize(
  77 |      address _winner,
  78 |      uint8 _tier,
  79 |      uint32 _prizeIndex,
  80 |      uint96 _reward,
  81 |      address _rewardRecipient
  82 |  ) external onlyClaimer returns (uint256) {
  :  |
     |      // @audit-issue _hooks read #1
  85 |      if (_hooks[_winner].useBeforeClaimPrize) {
     |          // @audit-issue _hooks read #2
  86 |          recipient = _hooks[_winner].implementation.beforeClaimPrize{ gas: HOOK_GAS }(
  :  |
     |      // @audit-issue _hooks read #3
 108 |      if (_hooks[_winner].useAfterClaimPrize) {
     |          // @audit-issue _hooks read #4
 109 |          _hooks[_winner].implementation.afterClaimPrize{ gas: HOOK_GAS }(
```

*GitHub* : [85](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L85), [86](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L86), [108](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L108), [109](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L109)

### [G-09]<a name="g-09"></a> Consider changing some `public` variables to `private`/`internal`

Public state variables in Solidity automatically generate getter functions, increasing deployment costs.
                    
Examples of variables that probably don't need to be public - anybody who needs to inspect them can check the on-chain contract storage:

* Factories
* Controllers
* Governance
* Owner, roles, etc.



*There are 16 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Reconsider whether this variable has to be public
  74 |  uint32 public constant FEE_PRECISION = 1e9;

     |  // @audit-issue Reconsider whether this variable has to be public
  80 |  uint32 public constant MAX_YIELD_FEE = 9e8;

     |  // @audit-issue Reconsider whether this variable has to be public
 112 |  uint256 public immutable yieldBuffer;

     |  // @audit-issue Reconsider whether this variable has to be public
 115 |  IERC4626 public immutable yieldVault;

     |  // @audit-issue Reconsider whether this variable has to be public
 119 |  uint32 public yieldFeePercentage;

     |  // @audit-issue Reconsider whether this variable has to be public
 122 |  address public yieldFeeRecipient;

     |  // @audit-issue Reconsider whether this variable has to be public
 125 |  uint256 public yieldFeeBalance;

     |  // @audit-issue Reconsider whether this variable has to be public
 128 |  address public liquidationPair;
```

*GitHub* : [74](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L74), [80](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L80), [112](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L112), [115](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L115), [119](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L119), [122](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L122), [125](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L125), [128](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L128)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Reconsider whether this variable has to be public
  63 |  uint256 public constant YIELD_BUFFER = 1e5;

     |  // @audit-issue Reconsider whether this variable has to be public
  66 |  PrizeVault[] public allVaults;

     |  // @audit-issue Reconsider whether this variable has to be public
  69 |  mapping(address vault => bool deployedByFactory) public deployedVaults;

     |  // @audit-issue Reconsider whether this variable has to be public
  72 |  mapping(address deployer => uint256 nonce) public deployerNonces;
```

*GitHub* : [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L63), [66](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L66), [69](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L69), [72](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L72)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Reconsider whether this variable has to be public
  26 |  TwabController public immutable twabController;
```

*GitHub* : [26](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L26)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Reconsider whether this variable has to be public
  21 |  uint24 public constant HOOK_GAS = 150_000;

     |  // @audit-issue Reconsider whether this variable has to be public
  24 |  PrizePool public immutable prizePool;

     |  // @audit-issue Reconsider whether this variable has to be public
  27 |  address public claimer;
```

*GitHub* : [21](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L21), [24](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L24), [27](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L27)

### [G-10]<a name="g-10"></a> Consider pre-calculating the address of `address(this)` to save gas

Instead of using `address(this)`, it is more gas-efficient to pre-calculate and use the hardcoded address. Foundry's `script.sol` and solmate's `LibRlp.sol` contracts can help achieve this.
Refrences:-[book.getfoundry](https://book.getfoundry.sh/reference/forge-std/compute-create-address)-[twitter](https://twitter.com/transmissions11/status/1518507047943245824).

*There are 23 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Pre-calculate & hardcode instead
 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 382 |  uint256 _latentBalance = _asset.balanceOf(address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 383 |  uint256 _maxYieldVaultDeposit = yieldVault.maxDeposit(address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 405 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 416 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 539 |  if (_asset.allowance(_owner, address(this)) != _assets) {

     |  // @audit-issue Pre-calculate & hardcode instead
 540 |  IERC20Permit(address(_asset)).permit(_owner, address(this), _assets, _deadline, _v, _r, _s);

     |  // @audit-issue Pre-calculate & hardcode instead
 558 |  if (twabController.delegateOf(address(this), _owner) != SPONSORSHIP_ADDRESS) {

     |  // @audit-issue Pre-calculate & hardcode instead
 634 |  if (_tokenOut == address(this)) {

     |  // @audit-issue Pre-calculate & hardcode instead
 639 |  _maxAmountOut = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 691 |  } else if (_tokenOut == address(this)) {

     |  // @audit-issue Pre-calculate & hardcode instead
 713 |  prizePool.contributePrizeTokens(address(this), _amountIn);

     |  // @audit-issue Pre-calculate & hardcode instead
 726 |  return (_tokenOut == address(_asset) || _tokenOut == address(this)) && _liquidationPair == liquidationPair;

     |  // @audit-issue Pre-calculate & hardcode instead
 747 |  emit LiquidationPairSet(address(this), address(_liquidationPair));

     |  // @audit-issue Pre-calculate & hardcode instead
 856 |  address(this),

     |  // @audit-issue Pre-calculate & hardcode instead
 861 |  uint256 _assetsWithDust = _asset.balanceOf(address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 866 |  uint256 _assetsUsed = yieldVault.mint(_yieldVaultShares, address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 922 |  return yieldVault.convertToAssets(yieldVault.maxRedeem(address(this)));

     |  // @audit-issue Pre-calculate & hardcode instead
 931 |  uint256 _latentAssets = _asset.balanceOf(address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 936 |  yieldVault.redeem(_yieldVaultShares, address(this), address(this));

     |  // @audit-issue Pre-calculate & hardcode instead
 938 |  if (_receiver != address(this)) {
```

*GitHub* : [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [382](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L382), [383](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L383), [405](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L405), [416](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L416), [539](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L539), [540](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L540), [558](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L558), [634](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L634), [639](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L639), [691](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L691), [713](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L713), [726](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L726), [747](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L747), [856](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L856), [861](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L861), [866](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L866), [922](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L922), [931](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L931), [936](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L936), [938](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L938)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Pre-calculate & hardcode instead
  59 |  return twabController.balanceOf(address(this), _account);

     |  // @audit-issue Pre-calculate & hardcode instead
  64 |  return twabController.totalSupply(address(this));
```

*GitHub* : [59](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L59), [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L64)

### [G-11]<a name="g-11"></a> Constructors can be marked `payable`

Payable functions cost less gas to execute, since the compiler does not have to add extra checks to ensure that a payment wasn't provided. A constructor can safely be marked as payable, since only the deployer would be able to pass funds, and the project itself would not pass any funds.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider marking payable to save gas
 289 |  constructor(
 290 |      string memory name_,
 291 |      string memory symbol_,
 292 |      IERC4626 yieldVault_,
 293 |      PrizePool prizePool_,
 294 |      address claimer_,
 295 |      address yieldFeeRecipient_,
 296 |      uint32 yieldFeePercentage_,
 297 |      uint256 yieldBuffer_,
 298 |      address owner_
 299 |  ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {
```

*GitHub* : [289-299](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L289-L299)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Consider marking payable to save gas
  42 |  constructor(
  43 |      string memory name_,
  44 |      string memory symbol_,
  45 |      TwabController twabController_
  46 |  ) ERC20(name_, symbol_) ERC20Permit(name_) {
```

*GitHub* : [42-46](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L42-L46)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider marking payable to save gas
  64 |  constructor(PrizePool prizePool_, address claimer_) {
```

*GitHub* : [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L64)

### [G-12]<a name="g-12"></a> Detect zero value transfers to save gas

Detecting and aborting zero value transfers will save at least 100 gas.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 939 |  _asset.transfer(_receiver, _assets);
```

*GitHub* : [939](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L939)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118)

### [G-13]<a name="g-13"></a> Divisions can be `unchecked` to save gas

The expression `type(int).min/(-1)` is the only case where division causes an overflow. Therefore, uncheck can be used to save gas in scenarios where it is certain that such an overflow will not occur.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Use unchecked to save gas, if possible
 675 |  _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;
```

*GitHub* : [675](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L675)

### [G-14]<a name="g-14"></a> Duplicated `require()`/`revert()` checks should be refactored to a modifier or function to save deployment gas

This will cost more runtime gas, but will reduce deployment gas when the function is (optionally called via a modifier) called more than once as is the case for the examples below. Most projects do not make this trade-off, but it's available nonetheless.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Duplicates of this conditional revert statement were detected
 612 |  if (_shares == 0) revert MintZeroShares();
  :  |
     |  // @audit-issue First seen at pt-v5-vault/src/PrizeVault.sol:612
 844 |  if (_shares == 0) revert MintZeroShares();
```

*GitHub* : [844](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L844)

### [G-15]<a name="g-15"></a> Emitting constants wastes gas

Every event parameter costs `Glogdata` (**8 gas**) per byte. You can avoid this extra cost, in cases where you're emitting a constant, by creating a new version of the event which doesn't have the parameter (and have users look to the contract's variables for its value instead). Alternatively, in the case of boolean constants, two events can be created - one representing the `true` case and one representing the `false` case.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/TwabERC20.sol

  78 |  emit Transfer(address(0), _receiver, _amount);

  89 |  emit Transfer(_owner, address(0), _amount);
```

*GitHub* : [78](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L78), [89](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L89)

### [G-16]<a name="g-16"></a> Enable IR-based code generation

By using `--via-ir` or `{"viaIR": true}`, the compiler is able to use more advanced [multi-function optimizations](https://docs.soliditylang.org/en/v0.8.17/ir-breaking-changes.html#solidity-ir-based-codegen-changes), for extra gas savings.

> 🔴 IR-based code generation was not observed to be enabled in the configuration.


*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Enable viaIR for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L1)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Enable viaIR for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L1)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Enable viaIR for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Enable viaIR for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Enable viaIR for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L1)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Enable viaIR for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L1)

### [G-17]<a name="g-17"></a> Function names can be optimized to save gas

Function that are `public`/`external` and `public` state variable names can be optimized to save gas.

Method IDs that have two leading zero bytes can save **128 gas** each during deployment, and renaming functions to have lower method IDs will save **22 gas** per call, per sorted position shifted. [Reference](https://blog.emn178.cc/en/post/solidity-gas-optimization-function-name/).

You can use the [Function Name Optimizer Tool](https://emn178.github.io/solidity-optimize-name/) to find new function names.

*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Can be optimized to two leading zeros:
     |  // 0x313ce567: decimals()
     |  // 0x38d52e0f: asset()
     |  // 0x01e1d114: totalAssets()
     |  // 0xc6e6f592: convertToShares()
     |  // 0x07a2d13a: convertToAssets()
     |  // 0x402d267d: maxDeposit()
     |  // 0xc63d75b6: maxMint()
     |  // 0xce96cb77: maxWithdraw()
     |  // 0xd905777e: maxRedeem()
     |  // 0xef8b30f7: previewDeposit()
     |  // 0xb3d7f6b9: previewMint()
     |  // 0x0a28a477: previewWithdraw()
     |  // 0x4cdad506: previewRedeem()
     |  // 0x6e553f65: deposit()
     |  // 0x94bf804d: mint()
     |  // 0xb460af94: withdraw()
     |  // 0xba087652: redeem()
     |  // 0x50921b23: depositWithPermit()
     |  // 0xb6cce5e2: sponsor()
     |  // 0xfc7b9c18: totalDebt()
     |  // 0xd4122abf: totalYieldBalance()
     |  // 0x0d1e5255: availableYieldBalance()
     |  // 0x237fd108: currentYieldBuffer()
     |  // 0x353d5a18: claimYieldFeeShares()
     |  // 0xb0fcf626: liquidatableBalanceOf()
     |  // 0x7cc99d3f: transferTokensOut()
     |  // 0xc8576e61: verifyTokensIn()
     |  // 0x700f04ef: targetOf()
     |  // 0x1b571924: isLiquidationPair()
     |  // 0xcdfb5832: setClaimer()
     |  // 0x25fa66e0: setLiquidationPair()
     |  // 0xe4e243ac: setYieldFeePercentage()
     |  // 0x63003b16: setYieldFeeRecipient()
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
```

*GitHub* : [65](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L65)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Can be optimized to two leading zeros:
     |  // 0xb688010c: deployVault()
     |  // 0x8d654023: totalVaults()
  13 |  contract PrizeVaultFactory {
```

*GitHub* : [13](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L13)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Can be optimized to two leading zeros:
     |  // 0x70a08231: balanceOf()
     |  // 0x18160ddd: totalSupply()
  19 |  contract TwabERC20 is ERC20, ERC20Permit {
```

*GitHub* : [19](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L19)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Can be optimized to two leading zeros:
     |  // 0x2895cace: claimPrize()
  13 |  abstract contract Claimable is HookManager, IClaimable {
```

*GitHub* : [13](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L13)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Can be optimized to two leading zeros:
     |  // 0xde03f408: getHooks()
     |  // 0xc78c72c1: setHooks()
   9 |  abstract contract HookManager {
```

*GitHub* : [9](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L9)

### [G-18]<a name="g-18"></a> Functions guaranteed to revert when called by normal users can be marked `payable`

If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided. The extra opcodes avoided are 
            `CALLVALUE`(2), `DUP1`(3), `ISZERO`(3), `PUSH2`(3), `JUMPI`(10), `PUSH1`(3), `DUP1`(3), `REVERT`(0), `JUMPDEST`(1), `POP`(2), which costs an average of about **21 gas per call** to the function, in addition to the extra deployment cost.

*There are 8 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider marking payable to save gas
 611 |  function claimYieldFeeShares(uint256 _shares) external onlyYieldFeeRecipient {

     |  // @audit-issue Consider marking payable to save gas
 659 |  function transferTokensOut(
 660 |      address,
 661 |      address _receiver,
 662 |      address _tokenOut,
 663 |      uint256 _amountOut
 664 |  ) public virtual onlyLiquidationPair returns (bytes memory) {

     |  // @audit-issue Consider marking payable to save gas
 703 |  function verifyTokensIn(
 704 |      address _tokenIn,
 705 |      uint256 _amountIn,
 706 |      bytes calldata
 707 |  ) external onlyLiquidationPair {

     |  // @audit-issue Consider marking payable to save gas
 735 |  function setClaimer(address _claimer) external onlyOwner {

     |  // @audit-issue Consider marking payable to save gas
 742 |  function setLiquidationPair(address _liquidationPair) external onlyOwner {

     |  // @audit-issue Consider marking payable to save gas
 753 |  function setYieldFeePercentage(uint32 _yieldFeePercentage) external onlyOwner {

     |  // @audit-issue Consider marking payable to save gas
 759 |  function setYieldFeeRecipient(address _yieldFeeRecipient) external onlyOwner {
```

*GitHub* : [611](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L611), [659-664](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L659-L664), [703-707](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L703-L707), [735](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L735), [742](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L742), [753](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L753), [759](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L759)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider marking payable to save gas
  76 |  function claimPrize(
  77 |      address _winner,
  78 |      uint8 _tier,
  79 |      uint32 _prizeIndex,
  80 |      uint96 _reward,
  81 |      address _rewardRecipient
  82 |  ) external onlyClaimer returns (uint256) {
```

*GitHub* : [76-82](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L76-L82)

### [G-19]<a name="g-19"></a> Inline `internal` functions that are only called once

Saves 20-40 gas per instance. See https://blog.soliditylang.org/2021/03/02/saving-gas-with-simple-inliner/ for more details.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Inline this function, it's only used once
 772 |  function _tryGetAssetDecimals(IERC20 asset_) internal view returns (bool, uint8) {
```

*GitHub* : [772](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L772)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Inline this function, it's only used once
 128 |  function _setClaimer(address _claimer) internal {
```

*GitHub* : [128](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L128)

### [G-20]<a name="g-20"></a> Inline `modifier`s that are only used once, to save gas

Inline `modifier`s that are only used once, to save gas.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Contains redundant modifiers
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
  :  |
     |      // @audit-issue This is the only invocation of this modifier
 611 |      function claimYieldFeeShares(uint256 _shares) external onlyYieldFeeRecipient {
```

*GitHub* : [611](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L611)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-info Contains redundant modifiers
  13 |  abstract contract Claimable is HookManager, IClaimable {
  :  |
     |      // @audit-issue This is the only invocation of this modifier
  82 |      ) external onlyClaimer returns (uint256) {
```

*GitHub* : [82](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L82)

### [G-21]<a name="g-21"></a> Mappings are cheaper to use than storage arrays

When using storage arrays, solidity adds an internal lookup of the array's length (a Gcoldsload **2100 gas**) to ensure you don't read past the array's end. You can avoid this lookup by using a `mapping` and storing the number of entries in a separate storage variable. In cases where you have sentinel values (e.g. 'zero' means invalid), you can avoid length checks.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

  66 |  PrizeVault[] public allVaults;
```

*GitHub* : [66](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L66)

### [G-22]<a name="g-22"></a> Multiple accesses of a mapping/array should use a local variable cache

The instances below point to multiple accesses of a value inside a mapping/array, within a function. Caching a mapping's value in a local `storage` or `calldata` variable when the value is accessed [multiple times](https://gist.github.com/IllIllI000/ec23a57daa30a8f8ca8b9681c8ccefb0), saves **~42 gas per access** due to not having to recalculate the key's keccak256 hash (Gkeccak256 - **30 gas**) and that calculation's associated stack operations. Caching an array's struct avoids recalculating the array offsets into memory/calldata

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-info Context
  76 |  function claimPrize(
  77 |      address _winner,
  78 |      uint8 _tier,
  79 |      uint32 _prizeIndex,
  80 |      uint96 _reward,
  81 |      address _rewardRecipient
  82 |  ) external onlyClaimer returns (uint256) {
  :  |
     |      // @audit-issue `_hooks[_winner]` usage #1
  85 |      if (_hooks[_winner].useBeforeClaimPrize) {
     |          // @audit-issue `_hooks[_winner]` usage #2
  86 |          recipient = _hooks[_winner].implementation.beforeClaimPrize{ gas: HOOK_GAS }(
  :  |
     |      // @audit-issue `_hooks[_winner]` usage #3
 108 |      if (_hooks[_winner].useAfterClaimPrize) {
     |          // @audit-issue `_hooks[_winner]` usage #4
 109 |          _hooks[_winner].implementation.afterClaimPrize{ gas: HOOK_GAS }(
```

*GitHub* : [85](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L85), [86](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L86), [108](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L108), [109](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L109)

### [G-23]<a name="g-23"></a> Nesting `if`-statements is cheaper than using `&&`

Nesting `if`-statements avoids the stack operations of setting up and using an extra `jumpdest`, and saves **6 [gas](https://gist.github.com/IllIllI000/7f3b818abecfadbef93b894481ae7d19)**

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider using nested ifs instead of && to save gas
 776 |  if (success && encodedDecimals.length >= 32) {
```

*GitHub* : [776](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L776)

### [G-24]<a name="g-24"></a> Only emit event in setter function if the state variable was changed

Emitting events in setter functions of smart contracts only when state variables change saves gas. This is because emitting events consumes gas, and unnecessary events, where no actual state change occurs, lead to wasteful consumption.

*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Unvalidated: _liquidationPair
 742 |  function setLiquidationPair(address _liquidationPair) external onlyOwner {
  :  |
     |      // @audit-issue Potentially redundant emit
 747 |      emit LiquidationPairSet(address(this), address(_liquidationPair));

     |  // @audit-info Unvalidated: _yieldFeePercentage
 947 |  function _setYieldFeePercentage(uint32 _yieldFeePercentage) internal {
  :  |
     |      // @audit-issue Potentially redundant emit
 952 |      emit YieldFeePercentageSet(_yieldFeePercentage);

     |  // @audit-info Unvalidated: _yieldFeeRecipient
 958 |  function _setYieldFeeRecipient(address _yieldFeeRecipient) internal {
  :  |
     |      // @audit-issue Potentially redundant emit
 960 |      emit YieldFeeRecipientSet(_yieldFeeRecipient);
```

*GitHub* : [747](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L747), [952](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L952), [960](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L960)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-info Unvalidated: _claimer
 128 |  function _setClaimer(address _claimer) internal {
  :  |
     |      // @audit-issue Potentially redundant emit
 131 |      emit ClaimerSet(_claimer);
```

*GitHub* : [131](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L131)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-info Unvalidated: hooks
  29 |  function setHooks(VaultHooks calldata hooks) external {
  :  |
     |      // @audit-issue Potentially redundant emit
  31 |      emit SetHooks(msg.sender, hooks);
```

*GitHub* : [31](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L31)

### [G-25]<a name="g-25"></a> Operator `>=`/`<=` costs less gas than operator `>`/`<`

The compiler uses opcodes `GT` and `ISZERO` for solidity code that uses `>`, but only requires `LT` for `>=`, [which saves **3 gas**](https://gist.github.com/IllIllI000/3dc79d25acccfa16dee4e83ffdc6ffde). If `<` is being used, the condition can be inverted.

*There are 10 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Switch > to >= and < to <=
 377 |  if (totalAssets() < totalDebt_) return 0;

     |  // @audit-issue Switch > to >= and < to <=
 390 |  return twabSupplyLimit_ < _maxDeposit ? twabSupplyLimit_ : _maxDeposit;

     |  // @audit-issue Switch > to >= and < to <=
 409 |  return _ownerAssets < _maxWithdraw ? _ownerAssets : _maxWithdraw;

     |  // @audit-issue Switch > to >= and < to <=
 422 |  if (_ownerShares > _maxWithdraw) {

     |  // @audit-issue Switch > to >= and < to <=
 615 |  if (_shares > _yieldFeeBalance) revert SharesExceedsYieldFeeBalance(_shares, _yieldFeeBalance);

     |  // @audit-issue Switch > to >= and < to <=
 679 |  if (_amountOut + _yieldFee > _availableYield) {

     |  // @audit-issue Switch > to >= and < to <=
 684 |  if (_yieldFee > 0) {

     |  // @audit-issue Switch > to >= and < to <=
 874 |  if (totalAssets() < totalDebt()) revert LossyDeposit(totalAssets(), totalDebt());

     |  // @audit-issue Switch > to >= and < to <=
 932 |  if (_assets > _latentAssets) {

     |  // @audit-issue Switch > to >= and < to <=
 948 |  if (_yieldFeePercentage > MAX_YIELD_FEE) {
```

*GitHub* : [377](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L377), [390](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L390), [409](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L409), [422](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L422), [615](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L615), [679](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L679), [684](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L684), [874](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L874), [932](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L932), [948](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L948)

### [G-26]<a name="g-26"></a> Public functions not used internally can be marked as external to save gas

Public functions that aren't used internally in Solidity contracts should be made external to optimize gas usage and improve contract efficiency. External functions can only be called from outside the contract, and their arguments are directly read from the calldata, which is more gas-efficient than loading them into memory, as is the case for public functions. By using external visibility, developers can reduce gas consumption for external calls and ensure that the contract operates more cost-effectively for users. Moreover, setting the appropriate visibility level for functions also enhances code readability and maintainability, promoting a more secure and well-structured contract design. 

*There are 10 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Context
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
  :  |
     |      // @audit-issue Not called internally by this contract
 320 |      function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {
  :  |
     |      // @audit-issue Not called internally by this contract
 341 |      function convertToShares(uint256 _assets) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 397 |      function maxMint(address _owner) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 404 |      function maxWithdraw(address _owner) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 415 |      function maxRedeem(address _owner) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 584 |      function totalYieldBalance() public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 631 |      function liquidatableBalanceOf(address _tokenOut) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 659 |      function transferTokensOut(
 660 |          address,
 661 |          address _receiver,
 662 |          address _tokenOut,
 663 |          uint256 _amountOut
 664 |      ) public virtual onlyLiquidationPair returns (bytes memory) {
```

*GitHub* : [320](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L320), [341](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L341), [397](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L397), [404](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L404), [415](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L415), [584](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L584), [631](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L631), [659-664](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L659-L664)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-info Context
  19 |  contract TwabERC20 is ERC20, ERC20Permit {
  :  |
     |      // @audit-issue Not called internally by this contract
  56 |      function balanceOf(
  57 |          address _account
  58 |      ) public view virtual override(ERC20) returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
  63 |      function totalSupply() public view virtual override(ERC20) returns (uint256) {
```

*GitHub* : [56-58](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L56-L58), [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L63)

### [G-27]<a name="g-27"></a> Reduce deployment gas costs by fine-tuning IPFS file hashes

Solc [currently by default](https://docs.soliditylang.org/en/v0.8.23/metadata.html#encoding-of-the-metadata-hash-in-the-bytecode) appends the IPFS hash (in CID v0) of the canonical metadata file and the compiler version to the end of the bytecode. This value is variable-length [CBOR-encoded](https://tools.ietf.org/html/rfc7049) i.e. it can be optimized in order to reduce deployment gas costs. See [this article] for more information (https://www.rareskills.io/post/solidity-metadata).
                    
*Note:* multiple contracts in the same file will share the same hash.

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue IPFS hash is dweb:/ipfs/QmcMHci3QzQtzfwvLJNUbMUbApah8QwkwgMCZsdHHTgXcr
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
```

*GitHub* : [65](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L65)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue IPFS hash is dweb:/ipfs/QmPmgq4k77FYP6RzH4Jrt14N9HdptQW1gBnexbKFLKHYYB
  13 |  contract PrizeVaultFactory {
```

*GitHub* : [13](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L13)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue IPFS hash is dweb:/ipfs/QmXhskESEmfkzcEdEuJ3x5WdVRjgFRs8xiGGFCsy4nvoFF
  19 |  contract TwabERC20 is ERC20, ERC20Permit {
```

*GitHub* : [19](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L19)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue IPFS hash is dweb:/ipfs/QmUWLj2LdjfCd9Fv4fFAdxLgPL2shkxHHU6Wxn8ezjddU2
  13 |  abstract contract Claimable is HookManager, IClaimable {
```

*GitHub* : [13](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L13)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue IPFS hash is dweb:/ipfs/QmPgUoXAbfrbeE3gHzeYLog7PMiGNsWgG7x6c518E4RT1q
   9 |  abstract contract HookManager {
```

*GitHub* : [9](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L9)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue IPFS hash is dweb:/ipfs/QmNdCpkpwXjQxDqiUuFTsdYHLs31i9jygY1gXuen6irp1G
  17 |  interface IVaultHooks {
```

*GitHub* : [17](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L17)

### [G-28]<a name="g-28"></a> Reduce gas usage by moving to Solidity 0.8.19 or later

See [this](https://blog.soliditylang.org/2023/02/22/solidity-0.8.19-release-announcement/#preventing-dead-code-in-runtime-bytecode) link for the full details.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Require Solidity 0.8.19 or later
   2 |  pragma solidity ^0.8.0;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L2)

### [G-29]<a name="g-29"></a> Redundant state variable getters

Getters for public state variables are automatically generated so there is no need to code them manually and lose gas

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 320 |  function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {
 321 |      return _underlyingDecimals;
 322 |  }
```

*GitHub* : [320-322](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L320-L322)

### [G-30]<a name="g-30"></a> Redundant type conversion

Casting a variable to its own type is redundant and a waste of gas.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue `address(_liquidationPair)` is a redundant type cast
 743 |  if (address(_liquidationPair) == address(0)) revert LPZeroAddress();

     |  // @audit-issue `address(_liquidationPair)` is a redundant type cast
 747 |  emit LiquidationPairSet(address(this), address(_liquidationPair));
```

*GitHub* : [743](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L743), [747](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L747)

### [G-31]<a name="g-31"></a> Refactor modifiers to call a local function

Modifiers code is copied in all instances where it's used, increasing bytecode size. If deployment gas costs are a concern for this contract, refactoring modifiers into functions can reduce bytecode size significantly at the cost of one JUMP.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Refactor to a function to save gas
 260 |  modifier onlyLiquidationPair() {

     |  // @audit-issue Refactor to a function to save gas
 268 |  modifier onlyYieldFeeRecipient() {
```

*GitHub* : [260](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L260), [268](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L268)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Refactor to a function to save gas
  52 |  modifier onlyClaimer() {
```

*GitHub* : [52](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L52)

### [G-32]<a name="g-32"></a> Replace OpenZeppelin components with Solady equivalents to save gas

The following OpenZeppelin imports have a [Solady](https://github.com/Vectorized/solady/tree/main) equivalent, as such they can be used to save GAS as Solady modules have been specifically designed to be as GAS efficient as possible.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider using the Solady implementation
   6 |  import { ERC20, IERC20, IERC20Metadata } from "openzeppelin/token/ERC20/ERC20.sol";
```

*GitHub* : [6](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L6)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider using the Solady implementation
   4 |  import { IERC20, IERC4626 } from "openzeppelin/token/ERC20/extensions/ERC4626.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L4)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Consider using the Solady implementation
   4 |  import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L4)

### [G-33]<a name="g-33"></a> Same cast is done multiple times

It's cheaper to do it once, and store the result to a variable.

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Contains redundant type conversions
 742 |  function setLiquidationPair(address _liquidationPair) external onlyOwner {
     |      // @audit-issue Cache this type conversion result that is used in multiple locations
 743 |      if (address(_liquidationPair) == address(0)) revert LPZeroAddress();
  :  |
     |      // @audit-issue Cache this type conversion result that is used in multiple locations
 747 |      emit LiquidationPairSet(address(this), address(_liquidationPair));

     |  // @audit-info Contains redundant type conversions
 843 |  function _depositAndMint(address _caller, address _receiver, uint256 _assets, uint256 _shares) internal {
  :  |
     |      // @audit-issue Cache this type conversion result that is used in multiple locations
 862 |      _asset.approve(address(yieldVault), _assetsWithDust);
  :  |
     |          // @audit-issue Cache this type conversion result that is used in multiple locations
 869 |          _asset.approve(address(yieldVault), 0);
```

*GitHub* : [743](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L743), [747](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L747), [862](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L862), [869](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L869)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-info Contains redundant type conversions
  92 |  function deployVault(
  93 |    string memory _name,
  94 |    string memory _symbol,
  95 |    IERC4626 _yieldVault,
  96 |    PrizePool _prizePool,
  97 |    address _claimer,
  98 |    address _yieldFeeRecipient,
  99 |    uint32 _yieldFeePercentage,
 100 |    address _owner
 101 |  ) external returns (PrizeVault) {
  :  |
     |      // @audit-issue Cache this type conversion result that is used in multiple locations
 118 |      IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
  :  |
     |      // @audit-issue Cache this type conversion result that is used in multiple locations
 121 |      deployedVaults[address(_vault)] = true;
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118), [121](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L121)

### [G-34]<a name="g-34"></a> Simple checks for zero can be done using assembly to save gas

Using assembly for simple zero checks on unsigned integers can save gas due to lower-level, optimized operations. 

*There are 8 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Use inline assembly
 458 |  if (_totalAssets == 0) revert ZeroTotalAssets();

     |  // @audit-issue Use inline assembly
 612 |  if (_shares == 0) revert MintZeroShares();

     |  // @audit-issue Use inline assembly
 665 |  if (_amountOut == 0) revert LiquidationAmountOutZero();

     |  // @audit-issue Use inline assembly
 672 |  if (_yieldFeePercentage != 0) {

     |  // @audit-issue Use inline assembly
 844 |  if (_shares == 0) revert MintZeroShares();

     |  // @audit-issue Use inline assembly
 845 |  if (_assets == 0) revert DepositZeroAssets();

     |  // @audit-issue Use inline assembly
 894 |  if (_assets == 0) revert WithdrawZeroAssets();

     |  // @audit-issue Use inline assembly
 895 |  if (_shares == 0) revert BurnZeroShares();
```

*GitHub* : [458](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L458), [612](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L612), [665](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L665), [672](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L672), [844](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L844), [845](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L845), [894](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L894), [895](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L895)

### [G-35]<a name="g-35"></a> Split `revert` checks to save gas

Splitting the conditions into two separate checks **2 gas**

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 679 |  if (_amountOut + _yieldFee > _availableYield) {
 680 |      revert LiquidationExceedsAvailable(_amountOut + _yieldFee, _availableYield);
 681 |  }
```

*GitHub* : [679-681](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L679-L681)

### [G-36]<a name="g-36"></a> Stack variable is only used once

If the variable is only accessed once, it's cheaper to use the assigned value directly that one time, and save the **3 gas** the extra stack assignment would spend.

*There are 45 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 320 |  function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {
  :  |
 329 |  function asset() external view returns (address) {
  :  |
 336 |  function totalAssets() public view returns (uint256) {
  :  |
 341 |  function convertToShares(uint256 _assets) public view returns (uint256) {
  :  |
 355 |  function convertToAssets(uint256 _shares) public view returns (uint256) {
  :  |
 374 |  function maxDeposit(address) public view returns (uint256) {
  :  |
 397 |  function maxMint(address _owner) public view returns (uint256) {
  :  |
 404 |  function maxWithdraw(address _owner) public view returns (uint256) {
  :  |
 415 |  function maxRedeem(address _owner) public view returns (uint256) {
  :  |
 441 |  function previewDeposit(uint256 _assets) public pure returns (uint256) {
  :  |
 447 |  function previewMint(uint256 _shares) public pure returns (uint256) {
  :  |
 454 |  function previewWithdraw(uint256 _assets) public view returns (uint256) {
  :  |
 470 |  function previewRedeem(uint256 _shares) public view returns (uint256) {
  :  |
 475 |  function deposit(uint256 _assets, address _receiver) external returns (uint256) {
  :  |
 482 |  function mint(uint256 _shares, address _receiver) external returns (uint256) {
  :  |
 493 |  ) external returns (uint256) {
  :  |
 504 |  ) external returns (uint256) {
  :  |
 531 |  ) external returns (uint256) {
  :  |
 552 |  function sponsor(uint256 _assets) external returns (uint256) {
  :  |
 573 |  function totalDebt() public view returns (uint256) {
  :  |
 584 |  function totalYieldBalance() public view returns (uint256) {
  :  |
 591 |  function availableYieldBalance() public view returns (uint256) {
  :  |
 597 |  function currentYieldBuffer() external view returns (uint256) {
  :  |
 631 |  function liquidatableBalanceOf(address _tokenOut) public view returns (uint256) {
  :  |
 660 |      address,
  :  |
 664 |  ) public virtual onlyLiquidationPair returns (bytes memory) {
  :  |
 706 |      bytes calldata
  :  |
 717 |  function targetOf(address) external view returns (address) {
  :  |
 725 |  ) external view returns (bool) {
  :  |
 772 |  function _tryGetAssetDecimals(IERC20 asset_) internal view returns (bool, uint8) {
  :  |
 790 |  function _totalDebt(uint256 _totalSupply) internal view returns (uint256) {
  :  |
 798 |  function _twabSupplyLimit(uint256 _totalSupply) internal pure returns (uint256) {
  :  |
 808 |  function _totalYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal pure returns (uint256) {
  :  |
 823 |  function _availableYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal view returns (uint256) {
  :  |
 921 |  function _maxYieldVaultWithdraw() internal view returns (uint256) {
```

*GitHub* : [320](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L320), [329](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L329), [336](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L336), [341](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L341), [355](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L355), [374](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L374), [374](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L374), [397](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L397), [404](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L404), [415](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L415), [441](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L441), [447](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L447), [454](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L454), [470](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L470), [475](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L475), [482](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L482), [493](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L493), [504](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L504), [531](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L531), [552](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L552), [573](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L573), [584](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L584), [591](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L591), [597](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L597), [631](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L631), [660](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L660), [664](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L664), [706](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L706), [717](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L717), [717](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L717), [725](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L725), [772](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L772), [772](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L772), [790](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L790), [798](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L798), [808](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L808), [823](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L823), [921](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L921)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

 101 |  ) external returns (PrizeVault) {
  :  |
 136 |  function totalVaults() external view returns (uint256) {
```

*GitHub* : [101](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L101), [136](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L136)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

  58 |  ) public view virtual override(ERC20) returns (uint256) {
  :  |
  63 |  function totalSupply() public view virtual override(ERC20) returns (uint256) {
```

*GitHub* : [58](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L58), [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L63)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

  82 |  ) external onlyClaimer returns (uint256) {
```

*GitHub* : [82](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L82)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

  22 |  function getHooks(address account) external view returns (VaultHooks memory) {
```

*GitHub* : [22](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L22)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

  32 |  ) external returns (address);
```

*GitHub* : [32](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L32)

### [G-37]<a name="g-37"></a> Subtraction can potentially be marked `unchecked` to save gas

In Solidity 0.8.x and above, arithmetic operations like subtraction automatically check for underflows and overflows, and revert the transaction if such a condition is met. This built-in safety feature provides a layer of security against potential numerical errors. However, these automatic checks also come with additional gas costs.

In some situations, you may already have a guard condition, like a require() statement or an if statement, that ensures the safety of the arithmetic operation. In such cases, the automatic check becomes redundant and leads to unnecessary gas expenditure.

For example, you may have a function that subtracts a smaller number from a larger one, and you may have already verified that the smaller number is indeed smaller. In this case, you're already sure that the subtraction operation won't underflow, so there's no need for the automatic check.

In these situations, you can use the unchecked { } block around the subtraction operation to skip the automatic check. This will reduce gas costs and make your contract more efficient, without sacrificing security. However, it's critical to use unchecked { } only when you're absolutely sure that the operation is safe.

*There are 8 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Use unchecked to save gas, if possible
 388 |  _maxDeposit = _maxYieldVaultDeposit - _latentBalance;

     |  // @audit-issue Use unchecked to save gas, if possible
 649 |  .mulDiv(FEE_PRECISION - yieldFeePercentage, FEE_PRECISION);

     |  // @audit-issue Use unchecked to save gas, if possible
 675 |  _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;

     |  // @audit-issue Use unchecked to save gas, if possible
 675 |  _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;

     |  // @audit-issue Use unchecked to save gas, if possible
 800 |  return type(uint96).max - _totalSupply;

     |  // @audit-issue Use unchecked to save gas, if possible
 813 |  return _totalAssets - totalDebt_;

     |  // @audit-issue Use unchecked to save gas, if possible
 828 |  return totalYieldBalance_ - _yieldBuffer;

     |  // @audit-issue Use unchecked to save gas, if possible
 934 |  uint256 _yieldVaultShares = yieldVault.previewWithdraw(_assets - _latentAssets);
```

*GitHub* : [388](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L388), [649](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L649), [675](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L675), [675](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L675), [800](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L800), [813](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L813), [828](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L828), [934](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L934)

### [G-38]<a name="g-38"></a> The result of function calls should be cached rather than re-calling the function

The instances below point to the second+ call of the function within a single function.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Called 2 times in _depositAndMint()
 874 |  if (totalAssets() < totalDebt()) revert LossyDeposit(totalAssets(), totalDebt());

     |  // @audit-issue Called 2 times in _depositAndMint()
 874 |  if (totalAssets() < totalDebt()) revert LossyDeposit(totalAssets(), totalDebt());

     |  // @audit-issue Called 2 times in _depositAndMint()
 874 |  if (totalAssets() < totalDebt()) revert LossyDeposit(totalAssets(), totalDebt());

     |  // @audit-issue Called 2 times in _depositAndMint()
 874 |  if (totalAssets() < totalDebt()) revert LossyDeposit(totalAssets(), totalDebt());
```

*GitHub* : [874](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L874), [874](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L874), [874](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L874), [874](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L874)

### [G-39]<a name="g-39"></a> Usage of non-`uint256`/`int256` types uses more gas

When using a smaller int/uint type it first needs to be converted to it's 256 bit counterpart to be operated upon, this increases the gas cost and thus should be avoided. However it does make sense to use smaller int/uint values within structs provided you pack the struct properly. 

*There are 22 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider u/int256
  74 |  uint32 public constant FEE_PRECISION = 1e9;

     |  // @audit-issue Consider u/int256
  80 |  uint32 public constant MAX_YIELD_FEE = 9e8;

     |  // @audit-issue Consider u/int256
 119 |  uint32 public yieldFeePercentage;

     |  // @audit-issue Consider u/int256
 138 |  uint8 private immutable _underlyingDecimals;

     |  // @audit-issue Consider u/int256
 296 |  uint32 yieldFeePercentage_,

     |  // @audit-issue Consider u/int256
 304 |  (bool success, uint8 assetDecimals) = _tryGetAssetDecimals(asset_);

     |  // @audit-issue Consider u/int256
 320 |  function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {

     |  // @audit-issue Consider u/int256
 528 |  uint8 _v,

     |  // @audit-issue Consider u/int256
 668 |  uint32 _yieldFeePercentage = yieldFeePercentage;

     |  // @audit-issue Consider u/int256
 753 |  function setYieldFeePercentage(uint32 _yieldFeePercentage) external onlyOwner {

     |  // @audit-issue Consider u/int256
 772 |  function _tryGetAssetDecimals(IERC20 asset_) internal view returns (bool, uint8) {

     |  // @audit-issue Consider u/int256
 947 |  function _setYieldFeePercentage(uint32 _yieldFeePercentage) internal {
```

*GitHub* : [74](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L74), [80](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L80), [119](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L119), [138](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L138), [296](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L296), [304](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L304), [320](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L320), [528](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L528), [668](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L668), [753](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L753), [772](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L772), [947](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L947)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider u/int256
  99 |  uint32 _yieldFeePercentage,
```

*GitHub* : [99](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L99)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider u/int256
  21 |  uint24 public constant HOOK_GAS = 150_000;

     |  // @audit-issue Consider u/int256
  78 |  uint8 _tier,

     |  // @audit-issue Consider u/int256
  79 |  uint32 _prizeIndex,

     |  // @audit-issue Consider u/int256
  80 |  uint96 _reward,
```

*GitHub* : [21](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L21), [78](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L78), [79](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L79), [80](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L80)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Consider u/int256
  28 |  uint8 tier,

     |  // @audit-issue Consider u/int256
  29 |  uint32 prizeIndex,

     |  // @audit-issue Consider u/int256
  30 |  uint96 reward,

     |  // @audit-issue Consider u/int256
  42 |  uint8 tier,

     |  // @audit-issue Consider u/int256
  43 |  uint32 prizeIndex,
```

*GitHub* : [28](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L28), [29](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L29), [30](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L30), [42](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L42), [43](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L43)

### [G-40]<a name="g-40"></a> Use != 0 instead of > 0

If possible, i.e. the range of the variable precludes negative values, consider using `!= 0` to save gas.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Use != 0 instead
 684 |  if (_yieldFee > 0) {
```

*GitHub* : [684](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L684)

### [G-41]<a name="g-41"></a> Use Solady library where possible to save gas

Utilizing gas-optimized math functions from libraries like [Solady](https://github.com/Vectorized/solady/blob/main/src/utils/FixedPointMathLib.sol) can lead to more efficient smart contracts.
This is particularly beneficial in contracts where these operations are frequently used.

For example, `(x * WAD) / y` can be replaced with Solady's `divWad()`.


*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider using the Solady library for this arithmetic
 672 |  if (_yieldFeePercentage != 0) {
 673 |      // The yield fee is calculated as a portion of the total yield being consumed, such that 
 674 |      // `total = amountOut + yieldFee` and `yieldFee / total = yieldFeePercentage`. 
 675 |      _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;
 676 |  }

     |  // @audit-issue Consider using the Solady library for this arithmetic
 675 |  _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;
```

*GitHub* : [672-676](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L672-L676), [675](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L675)

### [G-42]<a name="g-42"></a> Use `calldata` instead of `memory` for function arguments that are read only

When a function with a `memory` array is called externally, the `abi.decode()` step has to use a for-loop to copy each index of the `calldata` to the `memory` index. Each iteration of this for-loop costs at least 60 gas (i.e. 60 * `<mem_array>.length`). Using calldata directly, removes the need for such a loop in the contract code and runtime execution.  
                    
If the array is passed to an `internal` function which passes the array to another `internal` function where the array is modified and therefore `memory` is used in the `external` call, it's still more gas-efficient to use `calldata` when the external function uses modifiers, since the modifiers may prevent the `internal` functions from being called. `Structs` have the same overhead as an array of length one.

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider switching `name_` param to `calldata`
 290 |  string memory name_,
     |  // @audit-issue Consider switching `symbol_` param to `calldata`
 291 |  string memory symbol_,
```

*GitHub* : [290](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L290), [291](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L291)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider switching `_name` param to `calldata`
  93 |  string memory _name,
     |  // @audit-issue Consider switching `_symbol` param to `calldata`
  94 |  string memory _symbol,
```

*GitHub* : [93](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L93), [94](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L94)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Consider switching `name_` param to `calldata`
  43 |  string memory name_,
     |  // @audit-issue Consider switching `symbol_` param to `calldata`
  44 |  string memory symbol_,
```

*GitHub* : [43](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L43), [44](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L44)

### [G-43]<a name="g-43"></a> Use `private` rather than `public` for constants

If needed, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Switch visibility to private
  74 |  uint32 public constant FEE_PRECISION = 1e9;

     |  // @audit-issue Switch visibility to private
  80 |  uint32 public constant MAX_YIELD_FEE = 9e8;
```

*GitHub* : [74](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L74), [80](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L80)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Switch visibility to private
  63 |  uint256 public constant YIELD_BUFFER = 1e5;
```

*GitHub* : [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L63)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Switch visibility to private
  21 |  uint24 public constant HOOK_GAS = 150_000;
```

*GitHub* : [21](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L21)

### [G-44]<a name="g-44"></a> Use `uint256(1)`/`uint256(2)` instead of `true`/`false` to save gas for changes

Avoids a Gsset (**20000 gas**) when changing from `false` to `true`, after having been `true` in the past. Since most of the bools aren't changed twice in one transaction, I've counted the amount of gas as half of the full amount, for each variable.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

  69 |  mapping(address vault => bool deployedByFactory) public deployedVaults;
```

*GitHub* : [69](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L69)

### [G-45]<a name="g-45"></a> Use assembly to calculate hashes

If the arguments to the encode call can fit into the scratch space (two words or fewer), then it's more efficient to use assembly to generate the hash (**80 gas**):
                    
```solidity
    keccak256(abi.encodePacked(a, b)); }
```

to

```solidity 
    assembly {
        mstore(0x00, a)
        mstore(0x20, b)
        let result := keccak256(0x00, 0x40)
    }
```

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Use assembly to calcuate hashes
 103 |  salt: keccak256(abi.encode(msg.sender, deployerNonces[msg.sender]++))
```

*GitHub* : [103](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L103)

### [G-46]<a name="g-46"></a> Use assembly to perform external calls, in order to save gas

Using Solidity's assembly scratch space for constructing calldata in external calls with one or two arguments can be a gas-efficient approach. This method leverages the designated memory area (the first 64 bytes of memory) for temporary data storage during assembly operations. By directly writing arguments into this scratch space, it eliminates the need for additional memory allocation typically required for calldata preparation. This technique can lead to notable gas savings, especially in high-frequency or gas-sensitive operations. However, it requires careful implementation to avoid data corruption and should be used with a thorough understanding of low-level EVM operations and memory handling. Proper testing and validation are crucial when employing such optimizations.

*There are 13 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Save gas by call this in assembly
 299 |  ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {

     |  // @audit-issue Save gas by call this in assembly
 303 |  IERC20 asset_ = IERC20(yieldVault_.asset());

     |  // @audit-issue Save gas by call this in assembly
 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 382 |  uint256 _latentBalance = _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 383 |  uint256 _maxYieldVaultDeposit = yieldVault.maxDeposit(address(this));

     |  // @audit-issue Save gas by call this in assembly
 405 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 416 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 539 |  if (_asset.allowance(_owner, address(this)) != _assets) {

     |  // @audit-issue Save gas by call this in assembly
 558 |  if (twabController.delegateOf(address(this), _owner) != SPONSORSHIP_ADDRESS) {

     |  // @audit-issue Save gas by call this in assembly
 559 |  twabController.sponsor(_owner);

     |  // @audit-issue Save gas by call this in assembly
 639 |  _maxAmountOut = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));
```

*GitHub* : [299](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L299), [303](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L303), [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [382](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L382), [383](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L383), [405](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L405), [416](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L416), [539](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L539), [558](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L558), [559](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L559), [639](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L639)

### [G-47]<a name="g-47"></a> Use assembly to write storage values

Instead of:
                    
```solidity
owner = _newOwner
```

write:

```solidity
assembly { sstore(owner.slot, _newOwner) }
```


*There are 14 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Use assembly `sstore` to save gas
 305 |  _underlyingDecimals = success ? assetDecimals : 18;

     |  // @audit-issue Use assembly `sstore` to save gas
 306 |  _asset = asset_;

     |  // @audit-issue Use assembly `sstore` to save gas
 308 |  yieldVault = yieldVault_;

     |  // @audit-issue Use assembly `sstore` to save gas
 309 |  yieldBuffer = yieldBuffer_;

     |  // @audit-issue Use assembly `sstore` to save gas
 617 |  yieldFeeBalance -= _yieldFeeBalance;

     |  // @audit-issue Use assembly `sstore` to save gas
 685 |  yieldFeeBalance += _yieldFee;

     |  // @audit-issue Use assembly `sstore` to save gas
 745 |  liquidationPair = _liquidationPair;

     |  // @audit-issue Use assembly `sstore` to save gas
 951 |  yieldFeePercentage = _yieldFeePercentage;

     |  // @audit-issue Use assembly `sstore` to save gas
 959 |  yieldFeeRecipient = _yieldFeeRecipient;
```

*GitHub* : [305](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L305), [306](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L306), [308](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L308), [309](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L309), [617](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L617), [685](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L685), [745](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L745), [951](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L951), [959](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L959)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Use assembly `sstore` to save gas
 121 |  deployedVaults[address(_vault)] = true;
```

*GitHub* : [121](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L121)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Use assembly `sstore` to save gas
  48 |  twabController = twabController_;
```

*GitHub* : [48](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L48)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Use assembly `sstore` to save gas
  66 |  prizePool = prizePool_;

     |  // @audit-issue Use assembly `sstore` to save gas
 130 |  claimer = _claimer;
```

*GitHub* : [66](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L66), [130](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L130)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Use assembly `sstore` to save gas
  30 |  _hooks[msg.sender] = hooks;
```

*GitHub* : [30](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L30)

### [G-48]<a name="g-48"></a> Use more recent OpenZeppelin version for gas boost

OpenZeppelin version 4.9.0+ provides many small gas optimizations, see [here](https://github.com/OpenZeppelin/openzeppelin-contracts/releases/tag/v4.9.0) for more info.

*There are 8 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC4626.sol)"
   4 |  import { IERC4626 } from "openzeppelin/interfaces/IERC4626.sol";

     |  // @audit-issue OpenZeppelin 4.9.3 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.3) (token/ERC20/utils/SafeERC20.sol)"
   5 |  import { SafeERC20, IERC20Permit } from "openzeppelin/token/ERC20/utils/SafeERC20.sol";

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/ERC20.sol)"
   6 |  import { ERC20, IERC20, IERC20Metadata } from "openzeppelin/token/ERC20/ERC20.sol";

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)"
   7 |  import { Math } from "openzeppelin/utils/math/Math.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L4), [5](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L5), [6](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L6), [7](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L7)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/extensions/ERC4626.sol)"
   4 |  import { IERC20, IERC4626 } from "openzeppelin/token/ERC20/extensions/ERC4626.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L4)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/ERC20.sol)"
   4 |  import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";

     |  // @audit-issue OpenZeppelin 4.9.4 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.4) (token/ERC20/extensions/ERC20Permit.sol)"
   5 |  import { ERC20Permit } from "openzeppelin/token/ERC20/extensions/ERC20Permit.sol";

     |  // @audit-issue OpenZeppelin 4.8.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SafeCast.sol)"
   6 |  import { SafeCast } from "openzeppelin/utils/math/SafeCast.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L4), [5](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L5), [6](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L6)

### [G-49]<a name="g-49"></a> Use named `return` parameters

Using named return values instead of explicitly calling `return` saves ~13 execution gas per call and >1000 deployment gas per instance.

*There are 40 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Provide names for all return parameters
 320 |  function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {

     |  // @audit-issue Provide names for all return parameters
 329 |  function asset() external view returns (address) {

     |  // @audit-issue Provide names for all return parameters
 336 |  function totalAssets() public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 341 |  function convertToShares(uint256 _assets) public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 355 |  function convertToAssets(uint256 _shares) public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 374 |  function maxDeposit(address) public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 397 |  function maxMint(address _owner) public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 404 |  function maxWithdraw(address _owner) public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 415 |  function maxRedeem(address _owner) public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 441 |  function previewDeposit(uint256 _assets) public pure returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 447 |  function previewMint(uint256 _shares) public pure returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 454 |  function previewWithdraw(uint256 _assets) public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 470 |  function previewRedeem(uint256 _shares) public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 475 |  function deposit(uint256 _assets, address _receiver) external returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 482 |  function mint(uint256 _shares, address _receiver) external returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 489 |  function withdraw(
 490 |      uint256 _assets,
 491 |      address _receiver,
 492 |      address _owner
 493 |  ) external returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 500 |  function redeem(
 501 |      uint256 _shares,
 502 |      address _receiver,
 503 |      address _owner
 504 |  ) external returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 524 |  function depositWithPermit(
 525 |      uint256 _assets,
 526 |      address _owner,
 527 |      uint256 _deadline,
 528 |      uint8 _v,
 529 |      bytes32 _r,
 530 |      bytes32 _s
 531 |  ) external returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 552 |  function sponsor(uint256 _assets) external returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 573 |  function totalDebt() public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 584 |  function totalYieldBalance() public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 591 |  function availableYieldBalance() public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 597 |  function currentYieldBuffer() external view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 631 |  function liquidatableBalanceOf(address _tokenOut) public view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 659 |  function transferTokensOut(
 660 |      address,
 661 |      address _receiver,
 662 |      address _tokenOut,
 663 |      uint256 _amountOut
 664 |  ) public virtual onlyLiquidationPair returns (bytes memory) {

     |  // @audit-issue Provide names for all return parameters
 717 |  function targetOf(address) external view returns (address) {

     |  // @audit-issue Provide names for all return parameters
 722 |  function isLiquidationPair(
 723 |      address _tokenOut,
 724 |      address _liquidationPair
 725 |  ) external view returns (bool) {

     |  // @audit-issue Provide names for all return parameters
 772 |  function _tryGetAssetDecimals(IERC20 asset_) internal view returns (bool, uint8) {

     |  // @audit-issue Provide names for all return parameters
 790 |  function _totalDebt(uint256 _totalSupply) internal view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 798 |  function _twabSupplyLimit(uint256 _totalSupply) internal pure returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 808 |  function _totalYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal pure returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 823 |  function _availableYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal view returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
 921 |  function _maxYieldVaultWithdraw() internal view returns (uint256) {
```

*GitHub* : [320](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L320), [329](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L329), [336](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L336), [341](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L341), [355](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L355), [374](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L374), [397](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L397), [404](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L404), [415](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L415), [441](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L441), [447](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L447), [454](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L454), [470](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L470), [475](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L475), [482](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L482), [489-493](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L489-L493), [500-504](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L500-L504), [524-531](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L524-L531), [552](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L552), [573](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L573), [584](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L584), [591](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L591), [597](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L597), [631](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L631), [659-664](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L659-L664), [717](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L717), [722-725](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L722-L725), [772](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L772), [790](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L790), [798](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L798), [808](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L808), [823](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L823), [921](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L921)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Provide names for all return parameters
  92 |  function deployVault(
  93 |    string memory _name,
  94 |    string memory _symbol,
  95 |    IERC4626 _yieldVault,
  96 |    PrizePool _prizePool,
  97 |    address _claimer,
  98 |    address _yieldFeeRecipient,
  99 |    uint32 _yieldFeePercentage,
 100 |    address _owner
 101 |  ) external returns (PrizeVault) {

     |  // @audit-issue Provide names for all return parameters
 136 |  function totalVaults() external view returns (uint256) {
```

*GitHub* : [92-101](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L92-L101), [136](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L136)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Provide names for all return parameters
  56 |  function balanceOf(
  57 |      address _account
  58 |  ) public view virtual override(ERC20) returns (uint256) {

     |  // @audit-issue Provide names for all return parameters
  63 |  function totalSupply() public view virtual override(ERC20) returns (uint256) {
```

*GitHub* : [56-58](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L56-L58), [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L63)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Provide names for all return parameters
  76 |  function claimPrize(
  77 |      address _winner,
  78 |      uint8 _tier,
  79 |      uint32 _prizeIndex,
  80 |      uint96 _reward,
  81 |      address _rewardRecipient
  82 |  ) external onlyClaimer returns (uint256) {
```

*GitHub* : [76-82](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L76-L82)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Provide names for all return parameters
  22 |  function getHooks(address account) external view returns (VaultHooks memory) {
```

*GitHub* : [22](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L22)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Provide names for all return parameters
  26 |  function beforeClaimPrize(
  27 |      address winner,
  28 |      uint8 tier,
  29 |      uint32 prizeIndex,
  30 |      uint96 reward,
  31 |      address rewardRecipient
  32 |  ) external returns (address);
```

*GitHub* : [26-32](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L26-L32)

### [G-50]<a name="g-50"></a> Use nested `if`s instead of `&&`

Optimization of condition checks in your smart contract is a crucial aspect in ensuring gas efficiency. Specifically, substituting multiple `&&` checks with nested `if` statements can lead to substantial gas savings.

When evaluating multiple conditions within a single `if` statement using the `&&` operator, each condition will consume gas even if a preceding condition fails. However, if these checks are broken down into nested `if` statements, execution halts as soon as a condition fails, saving the gas that would have been consumed by subsequent checks.

This practice is especially beneficial in scenarios where the `if` statement isn't followed by an `else` statement. The reason being, when an `else` statement is present, all conditions must be checked regardless to determine the correct branch of execution.

By reworking your code to utilize nested `if` statements, you can optimize gas usage, reduce execution cost, and enhance your contract's performance.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Save gas by using nested `if`
 776 |  if (success && encodedDecimals.length >= 32) {
```

*GitHub* : [776](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L776)

### [G-51]<a name="g-51"></a> Using `bool`s for storage incurs overhead

```solidity
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.
```
https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27
Use `uint256(0)` and `uint256(1)` for true/false to avoid a Gwarmaccess (**[100 gas](https://gist.github.com/IllIllI000/1b70014db712f8572a72378321250058)**) for the extra SLOAD

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

  69 |  mapping(address vault => bool deployedByFactory) public deployedVaults;
```

*GitHub* : [69](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L69)

### [G-52]<a name="g-52"></a> `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)

Try pre-increment (`++i`) or pre-decrement (`--i`).

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Switch to the pre-increment/decrement form
 103 |  salt: keccak256(abi.encode(msg.sender, deployerNonces[msg.sender]++))
```

*GitHub* : [103](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L103)

### [G-53]<a name="g-53"></a> `<x> += <y>` costs more gas than `<x> = <x> + <y>` for state variables

Using the addition operator instead of plus-equals saves **[113 gas](https://gist.github.com/IllIllI000/cbbfb267425b898e5be734d4008d4fe8)**

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Switch to <x> + <y> and <x> - <y>
 617 |  yieldFeeBalance -= _yieldFeeBalance;

     |  // @audit-issue Switch to <x> + <y> and <x> - <y>
 685 |  yieldFeeBalance += _yieldFee;
```

*GitHub* : [617](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L617), [685](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L685)

### [G-54]<a name="g-54"></a> `abi.encode()` is less efficient than `abi.encodepacked()` for non-address arguments

See for more information: https://github.com/ConnorBlockchain/Solidity-Encode-Gas-Comparison

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider `abi.encodePacked()`
 103 |  salt: keccak256(abi.encode(msg.sender, deployerNonces[msg.sender]++))
```

*GitHub* : [103](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L103)

### NonCritical Risk Issues

### [N-01]<a name="n-01"></a> Add inline comments for unnamed variables

`function foo(address x, address)` -> `function foo(address x, address /* y */)`

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider inline comments for the unnamed variable here
 374 |  function maxDeposit(address) public view returns (uint256) {

     |  // @audit-issue Consider inline comments for the unnamed variable here
 660 |  address,

     |  // @audit-issue Consider inline comments for the unnamed variable here
 706 |  bytes calldata

     |  // @audit-issue Consider inline comments for the unnamed variable here
 717 |  function targetOf(address) external view returns (address) {
```

*GitHub* : [374](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L374), [660](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L660), [706](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L706), [717](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L717)

### [N-02]<a name="n-02"></a> Complex arithmetic expression

To maintain readability in code, particularly in Solidity which can involve complex mathematical operations, it is often recommended to limit the number of arithmetic operations to a maximum of 2-3 per line. Too many operations in a single line can make the code difficult to read and understand, increase the likelihood of mistakes, and complicate the process of debugging and reviewing the code. Consider splitting such operations over more than one line, take special care when dealing with division however. Try to limit the number of arithmetic operations to a maximum of 3 per statement.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Simplify by using intermediate variables
 675 |  _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;
```

*GitHub* : [675](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L675)

### [N-03]<a name="n-03"></a> Consider adding a block/deny-list

Doing so will significantly increase centralization, but will help to prevent hackers from using stolen tokens.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider adding a block/deny-list
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
```

*GitHub* : [65](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L65)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Consider adding a block/deny-list
  19 |  contract TwabERC20 is ERC20, ERC20Permit {
```

*GitHub* : [19](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L19)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Consider adding a block/deny-list
   9 |  abstract contract HookManager {
```

*GitHub* : [9](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L9)

### [N-04]<a name="n-04"></a> Consider adding emergency-stop functionality

Adding a way to quickly halt protocol functionality in an emergency, rather than having to pause individual contracts one-by-one, will make in-progress hack mitigation faster and much less stressful.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider adding emergency-stop functionality
  13 |  contract PrizeVaultFactory {
```

*GitHub* : [13](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L13)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Consider adding emergency-stop functionality
   9 |  abstract contract HookManager {
```

*GitHub* : [9](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L9)

### [N-05]<a name="n-05"></a> Consider adding formal verification proofs

Consider using formal verification to mathematically prove that your code does what is intended, and does not have any edge cases with unexpected behavior. The solidity compiler itself has this functionality [built in](https://docs.soliditylang.org/en/latest/smtchecker.html#smtchecker-and-formal-verification).            
            

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L1)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L1)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L1)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L1)

### [N-06]<a name="n-06"></a> Consider adding validation of user inputs

There are no validations done on the arguments below. Consider that the Solidity [documentation](https://docs.soliditylang.org/en/latest/control-structures.html#panic-via-assert-and-error-via-require) states that `Properly functioning code should never create a Panic, not even on invalid external input. If this happens, then there is a bug in your contract which you should fix`. This means that there should be explicit checks for expected ranges of inputs. Underflows/overflows result in panics should not be used as range checks, and allowing funds to be sent to  `0x0`, which is the default value of address variables and has many gotchas, should be avoided.

*There are 26 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Validate `_assets`
 341 |  function convertToShares(uint256 _assets) public view returns (uint256) {

     |  // @audit-issue Validate `_shares`
 355 |  function convertToAssets(uint256 _shares) public view returns (uint256) {

     |  // @audit-issue Validate ``
 374 |  function maxDeposit(address) public view returns (uint256) {

     |  // @audit-issue Validate `_owner`
 397 |  function maxMint(address _owner) public view returns (uint256) {

     |  // @audit-issue Validate `_owner`
 404 |  function maxWithdraw(address _owner) public view returns (uint256) {

     |  // @audit-issue Validate `_owner`
 415 |  function maxRedeem(address _owner) public view returns (uint256) {

     |  // @audit-issue Validate `_assets`
 441 |  function previewDeposit(uint256 _assets) public pure returns (uint256) {

     |  // @audit-issue Validate `_shares`
 447 |  function previewMint(uint256 _shares) public pure returns (uint256) {

     |  // @audit-issue Validate `_assets`
 454 |  function previewWithdraw(uint256 _assets) public view returns (uint256) {

     |  // @audit-issue Validate `_shares`
 470 |  function previewRedeem(uint256 _shares) public view returns (uint256) {

     |  // @audit-issue Validate `_assets`
     |  // Validate `_receiver`
 475 |  function deposit(uint256 _assets, address _receiver) external returns (uint256) {

     |  // @audit-issue Validate `_shares`
     |  // Validate `_receiver`
 482 |  function mint(uint256 _shares, address _receiver) external returns (uint256) {

     |  // @audit-issue Validate `_assets`
     |  // Validate `_receiver`
     |  // Validate `_owner`
 489 |  function withdraw(
 490 |      uint256 _assets,
 491 |      address _receiver,
 492 |      address _owner
 493 |  ) external returns (uint256) {

     |  // @audit-issue Validate `_shares`
     |  // Validate `_receiver`
     |  // Validate `_owner`
 500 |  function redeem(
 501 |      uint256 _shares,
 502 |      address _receiver,
 503 |      address _owner
 504 |  ) external returns (uint256) {

     |  // @audit-issue Validate `_deadline`
     |  // Validate `_v`
     |  // Validate `_r`
     |  // Validate `_s`
 524 |  function depositWithPermit(
 525 |      uint256 _assets,
 526 |      address _owner,
 527 |      uint256 _deadline,
 528 |      uint8 _v,
 529 |      bytes32 _r,
 530 |      bytes32 _s
 531 |  ) external returns (uint256) {

     |  // @audit-issue Validate `_assets`
 552 |  function sponsor(uint256 _assets) external returns (uint256) {

     |  // @audit-issue Validate ``
     |  // Validate `_receiver`
 659 |  function transferTokensOut(
 660 |      address,
 661 |      address _receiver,
 662 |      address _tokenOut,
 663 |      uint256 _amountOut
 664 |  ) public virtual onlyLiquidationPair returns (bytes memory) {

     |  // @audit-issue Validate `_amountIn`
     |  // Validate ``
 703 |  function verifyTokensIn(
 704 |      address _tokenIn,
 705 |      uint256 _amountIn,
 706 |      bytes calldata
 707 |  ) external onlyLiquidationPair {

     |  // @audit-issue Validate ``
 717 |  function targetOf(address) external view returns (address) {
```

*GitHub* : [341](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L341), [355](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L355), [374](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L374), [397](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L397), [404](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L404), [415](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L415), [441](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L441), [447](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L447), [454](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L454), [470](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L470), [475](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L475), [482](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L482), [489-493](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L489-L493), [500-504](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L500-L504), [524-531](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L524-L531), [552](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L552), [659-664](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L659-L664), [703-707](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L703-L707), [717](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L717)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Validate `_name`
     |  // Validate `_symbol`
     |  // Validate `_yieldVault`
     |  // Validate `_prizePool`
     |  // Validate `_claimer`
     |  // Validate `_yieldFeeRecipient`
     |  // Validate `_yieldFeePercentage`
     |  // Validate `_owner`
  92 |  function deployVault(
  93 |    string memory _name,
  94 |    string memory _symbol,
  95 |    IERC4626 _yieldVault,
  96 |    PrizePool _prizePool,
  97 |    address _claimer,
  98 |    address _yieldFeeRecipient,
  99 |    uint32 _yieldFeePercentage,
 100 |    address _owner
 101 |  ) external returns (PrizeVault) {
```

*GitHub* : [92-101](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L92-L101)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Validate `_account`
  56 |  function balanceOf(
  57 |      address _account
  58 |  ) public view virtual override(ERC20) returns (uint256) {
```

*GitHub* : [56-58](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L56-L58)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Validate `_winner`
     |  // Validate `_tier`
     |  // Validate `_prizeIndex`
     |  // Validate `_reward`
     |  // Validate `_rewardRecipient`
  76 |  function claimPrize(
  77 |      address _winner,
  78 |      uint8 _tier,
  79 |      uint32 _prizeIndex,
  80 |      uint96 _reward,
  81 |      address _rewardRecipient
  82 |  ) external onlyClaimer returns (uint256) {
```

*GitHub* : [76-82](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L76-L82)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Validate `account`
  22 |  function getHooks(address account) external view returns (VaultHooks memory) {

     |  // @audit-issue Validate `hooks`
  29 |  function setHooks(VaultHooks calldata hooks) external {
```

*GitHub* : [22](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L22), [29](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L29)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Validate `winner`
     |  // Validate `tier`
     |  // Validate `prizeIndex`
     |  // Validate `reward`
     |  // Validate `rewardRecipient`
  26 |  function beforeClaimPrize(
  27 |      address winner,
  28 |      uint8 tier,
  29 |      uint32 prizeIndex,
  30 |      uint96 reward,
  31 |      address rewardRecipient
  32 |  ) external returns (address);

     |  // @audit-issue Validate `winner`
     |  // Validate `tier`
     |  // Validate `prizeIndex`
     |  // Validate `prize`
     |  // Validate `recipient`
  40 |  function afterClaimPrize(
  41 |      address winner,
  42 |      uint8 tier,
  43 |      uint32 prizeIndex,
  44 |      uint256 prize,
  45 |      address recipient
  46 |  ) external;
```

*GitHub* : [26-32](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L26-L32), [40-46](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L40-L46)

### [N-07]<a name="n-07"></a> Consider disabling `renounceOwnership()`

If the plan for your project does not include eventually giving up all ownership control, consider overwriting OpenZeppelin's `Ownable`'s `renounceOwnership()` function in order to disable it.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider overriding `renounceOwnership` and disabling it
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
```

*GitHub* : [65](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L65)

### [N-08]<a name="n-08"></a> Consider emitting an event from `constructor`s

Use events to monitor deployments are successful and/or to signal significant changes to off-chain monitoring tools.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider emitting an event
 289 |  constructor(
 290 |      string memory name_,
 291 |      string memory symbol_,
 292 |      IERC4626 yieldVault_,
 293 |      PrizePool prizePool_,
 294 |      address claimer_,
 295 |      address yieldFeeRecipient_,
 296 |      uint32 yieldFeePercentage_,
 297 |      uint256 yieldBuffer_,
 298 |      address owner_
 299 |  ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {
```

*GitHub* : [289-299](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L289-L299)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Consider emitting an event
  42 |  constructor(
  43 |      string memory name_,
  44 |      string memory symbol_,
  45 |      TwabController twabController_
  46 |  ) ERC20(name_, symbol_) ERC20Permit(name_) {
```

*GitHub* : [42-46](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L42-L46)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider emitting an event
  64 |  constructor(PrizePool prizePool_, address claimer_) {
```

*GitHub* : [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L64)

### [N-09]<a name="n-09"></a> Consider making contracts `Upgradeable`

This allows for bugs to be fixed in production, at the expense of increased centralization.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider making this critical contract upgradeable
  13 |  contract PrizeVaultFactory {
```

*GitHub* : [13](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L13)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Consider making this critical contract upgradeable
   9 |  abstract contract HookManager {
```

*GitHub* : [9](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L9)

### [N-10]<a name="n-10"></a> Consider moving `msg.sender` checks to `modifier`s

Using `modifier`s makes the contract guard intention of the code more clear, and also guarantees no other code can run before the modifier runs.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Refactor into a modifier
 261 |  if (msg.sender != liquidationPair) {
 262 |      revert CallerNotLP(msg.sender, liquidationPair);
 263 |  }

     |  // @audit-issue Refactor into a modifier
 269 |  if (msg.sender != yieldFeeRecipient) {
 270 |      revert CallerNotYieldFeeRecipient(msg.sender, yieldFeeRecipient);
 271 |  }

     |  // @audit-issue Refactor into a modifier
 532 |  if (_owner != msg.sender) {
 533 |      revert PermitCallerNotOwner(msg.sender, _owner);
 534 |  }
```

*GitHub* : [261-263](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L261-L263), [269-271](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L269-L271), [532-534](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L532-L534)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Refactor into a modifier
  53 |  if (msg.sender != claimer) revert CallerNotClaimer(msg.sender, claimer);
```

*GitHub* : [53](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L53)

### [N-11]<a name="n-11"></a> Consider providing a ranged getter for array state variables

While the compiler automatically provides a getter for accessing single elements within a public state variable array, it doesn't provide a way to fetch the whole array, or subsets thereof. Consider adding a function to allow the fetching of slices of the array, especially if the contract doesn't already have multicall functionality.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Provide a ranged getter
  66 |  PrizeVault[] public allVaults;
```

*GitHub* : [66](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L66)

### [N-12]<a name="n-12"></a> Consider splitting complex checks into multiple steps

Assign the individual expression operations to intermediate local variables, and check against those instead.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Refactor sub-expressions into variables
 726 |  return (_tokenOut == address(_asset) || _tokenOut == address(this)) && _liquidationPair == liquidationPair;
```

*GitHub* : [726](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L726)

### [N-13]<a name="n-13"></a> Consider upgrading OpenZeppelin dependency to a newer version

The following dependencies can be updated to the versions specified noted.

*There are 8 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC4626.sol)"
   4 |  import { IERC4626 } from "openzeppelin/interfaces/IERC4626.sol";

     |  // @audit-issue OpenZeppelin 4.9.3 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.3) (token/ERC20/utils/SafeERC20.sol)"
   5 |  import { SafeERC20, IERC20Permit } from "openzeppelin/token/ERC20/utils/SafeERC20.sol";

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/ERC20.sol)"
   6 |  import { ERC20, IERC20, IERC20Metadata } from "openzeppelin/token/ERC20/ERC20.sol";

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)"
   7 |  import { Math } from "openzeppelin/utils/math/Math.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L4), [5](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L5), [6](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L6), [7](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L7)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/extensions/ERC4626.sol)"
   4 |  import { IERC20, IERC4626 } from "openzeppelin/token/ERC20/extensions/ERC4626.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L4)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue OpenZeppelin 4.9.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/ERC20.sol)"
   4 |  import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";

     |  // @audit-issue OpenZeppelin 4.9.4 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.9.4) (token/ERC20/extensions/ERC20Permit.sol)"
   5 |  import { ERC20Permit } from "openzeppelin/token/ERC20/extensions/ERC20Permit.sol";

     |  // @audit-issue OpenZeppelin 4.8.0 can be updated to 4.9.5
     |  // "// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SafeCast.sol)"
   6 |  import { SafeCast } from "openzeppelin/utils/math/SafeCast.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L4), [5](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L5), [6](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L6)

### [N-14]<a name="n-14"></a> Consider using descriptive `constant`s when passing zero as a function argument

Passing `0` or `0x0` as a function argument can sometimes result in a security issue(e.g. passing zero as the slippage parameter). A historical example is the infamous `0x0` address bug where numerous tokens were lost. This happens because `0` can be interpreted as an uninitialized `address`, leading to transfers to the `0x0` `address`, effectively burning tokens. Moreover, `0` as a denominator in division operations would cause a runtime exception. It's also often indicative of a logical error in the caller's code.

Consider using a constant variable with a descriptive name, so it's clear that the argument is intentionally being used, and for the right reasons.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Replace literal 0 with an explicit constant
 869 |  _asset.approve(address(yieldVault), 0);
```

*GitHub* : [869](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L869)

### [N-15]<a name="n-15"></a> Consider using named function arguments

Named function calls in Solidity greatly improve code readability by explicitly mapping arguments to their respective parameter names. This clarity becomes critical when dealing with functions that have numerous or complex parameters, reducing potential errors due to misordered arguments. Therefore, adopting named function calls contributes to more maintainable and less error-prone code. The following findings are for function calls with 4 or more praameters.

*There are 12 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider named parameters
 477 |  _depositAndMint(msg.sender, _receiver, _assets, _shares);

     |  // @audit-issue Consider named parameters
 484 |  _depositAndMint(msg.sender, _receiver, _assets, _shares);

     |  // @audit-issue Consider named parameters
 495 |  _burnAndWithdraw(msg.sender, _receiver, _owner, _shares, _assets);

     |  // @audit-issue Consider named parameters
 506 |  _burnAndWithdraw(msg.sender, _receiver, _owner, _shares, _assets);

     |  // @audit-issue Consider named parameters
 540 |  IERC20Permit(address(_asset)).permit(_owner, address(this), _assets, _deadline, _v, _r, _s);

     |  // @audit-issue Consider named parameters
 544 |  _depositAndMint(_owner, _owner, _assets, _shares);

     |  // @audit-issue Consider named parameters
 556 |  _depositAndMint(_owner, _owner, _assets, _shares);

     |  // @audit-issue Consider named parameters
 697 |  emit TransferYieldOut(msg.sender, _tokenOut, _receiver, _amountOut, _yieldFee);

     |  // @audit-issue Consider named parameters
 876 |  emit Deposit(_caller, _receiver, _assets, _shares);

     |  // @audit-issue Consider named parameters
 909 |  emit Withdraw(_caller, _receiver, _owner, _assets, _shares);
```

*GitHub* : [477](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L477), [484](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L484), [495](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L495), [506](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L506), [540](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L540), [544](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L544), [556](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L556), [697](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L697), [876](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L876), [909](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L909)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider named parameters
 123 |  emit NewPrizeVault(
 124 |      _vault,
 125 |      _yieldVault,
 126 |      _prizePool,
 127 |      _name,
 128 |      _symbol
 129 |  );
```

*GitHub* : [123-129](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L123-L129)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider named parameters
  99 |  uint256 prizeTotal = prizePool.claimPrize(
 100 |      _winner,
 101 |      _tier,
 102 |      _prizeIndex,
 103 |      recipient,
 104 |      _reward,
 105 |      _rewardRecipient
 106 |  );
```

*GitHub* : [99-106](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L99-L106)

### [N-16]<a name="n-16"></a> Consider using named mappings

Consider using [named mappings](https://ethereum.stackexchange.com/a/145555) to make it easier to understand the purpose of each mapping (requires Solidity 0.8.18 or later).

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Name the key/value in this mapping
  17 |  mapping(address => VaultHooks) internal _hooks;
```

*GitHub* : [17](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L17)

### [N-17]<a name="n-17"></a> Consider using the `using`-`for` syntax

The `using`-`for` [syntax](https://docs.soliditylang.org/en/latest/contracts.html#using-for) is the more common way of calling library functions.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/TwabERC20.sol

  77 |  twabController.mint(_receiver, SafeCast.toUint96(_amount));

  88 |  twabController.burn(_owner, SafeCast.toUint96(_amount));

 101 |  twabController.transfer(_from, _to, SafeCast.toUint96(_amount));
```

*GitHub* : [77](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L77), [88](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L88), [101](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L101)

### [N-18]<a name="n-18"></a> Constructor / initialization function lacks parameter validation

Constructors and initialization functions play a critical role in contracts by setting important initial states when the contract is first deployed before the system starts. The parameters passed to the constructor and initialization functions directly affect the behavior of the contract / protocol. If incorrect parameters are provided, the system may fail to run, behave abnormally, be unstable, or lack security. Therefore, it's crucial to carefully check each parameter in the constructor and initialization functions. If an exception is found, the transaction should be rolled back.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue `yieldBuffer_` is assigned to a state variable, unvalidated
 289 |  constructor(
 290 |      string memory name_,
 291 |      string memory symbol_,
 292 |      IERC4626 yieldVault_,
 293 |      PrizePool prizePool_,
 294 |      address claimer_,
 295 |      address yieldFeeRecipient_,
 296 |      uint32 yieldFeePercentage_,
 297 |      uint256 yieldBuffer_,
 298 |      address owner_
 299 |  ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {
```

*GitHub* : [289-299](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L289-L299)

### [N-19]<a name="n-19"></a> Contract order does not follow Solidity style guide recommendations

This is a [best practice](https://docs.soliditylang.org/en/latest/style-guide.html#order-of-layout) that should be followed.

Inside each contract, library or interface, use the following order:

> 1. Type declarations
> 2. State variables
> 3. Events
> 4. Errors
> 5. Modifiers
> 6. Functions

Note that the recommendations here only cover the top-level ordering. Within, e.g. variables and functions, additional ordering rules will apply, but are covered by other findings.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-info Contract component order has style violations; recommended top-level order:
     |  // variable YIELD_BUFFER
     |  // variable allVaults
     |  // variable deployedVaults
     |  // variable deployerNonces
     |  // event NewPrizeVault
     |  // function deployVault
     |  // function totalVaults
  13 |  contract PrizeVaultFactory {
  :  |
     |      // @audit-issue variable YIELD_BUFFER should come before event NewPrizeVault
  63 |      uint256 public constant YIELD_BUFFER = 1e5;
```

*GitHub* : [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L63)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-info Contract component order has style violations; recommended top-level order:
     |  // variable _hooks
     |  // event SetHooks
     |  // function getHooks
     |  // function setHooks
   9 |  abstract contract HookManager {
  :  |
     |      // @audit-issue variable _hooks should come before event SetHooks
  17 |      mapping(address => VaultHooks) internal _hooks;
```

*GitHub* : [17](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L17)

### [N-20]<a name="n-20"></a> Contract should expose an `interface`

The `contract`s should expose an `interface` so that other projects can more easily integrate with it, without having to develop their own non-standard variants.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider defining an interface for this contract
  13 |  contract PrizeVaultFactory {
```

*GitHub* : [13](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L13)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Consider defining an interface for this contract
  19 |  contract TwabERC20 is ERC20, ERC20Permit {
```

*GitHub* : [19](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L19)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Consider defining an interface for this contract
   9 |  abstract contract HookManager {
```

*GitHub* : [9](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L9)

### [N-21]<a name="n-21"></a> Contracts and libraries should use fixed compiler versions

To prevent the actual contracts being deployed from behaving differently depending on the compiler version, it is recommended to use fixed solidity versions for contracts and libraries.

Although we can configure a specific version through config (like hardhat, forge config files), it is recommended to **set the fixed version in the solidity pragma directly** before deploying to the mainnet.

*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L2)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L2)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L2)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L2)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

   2 |  pragma solidity ^0.8.0;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L2)

### [N-22]<a name="n-22"></a> Contracts should have full test coverage

While 100% code coverage does not guarantee that there are no bugs, it often will catch easy-to-find bugs, and will ensure that there are fewer regressions when the code invariably has to be modified. Furthermore, in order to get full coverage, code authors will often have to re-organize their code so that it is more modular, so that each component can be tested separately, which reduces interdependencies between modules and layers, and makes for code that is easier to reason about and audit.

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Test coverage for this file was < 100%
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L1)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Test coverage for this file was < 100%
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L1)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Test coverage for this file was < 100%
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Test coverage for this file was < 100%
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Test coverage for this file was < 100%
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L1)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Test coverage for this file was < 100%
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L1)

### [N-23]<a name="n-23"></a> Critical system parameter changes should be behind a timelock

Admin functions that change state should consider adding timelocks so that users and other privileged roles can be notified of and react to upcoming changes. Also, this protects users against a compromised/malicious admin account.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Add a timelock to the parameter change
 735 |  function setClaimer(address _claimer) external onlyOwner {
 736 |      _setClaimer(_claimer);
 737 |  }

     |  // @audit-issue Add a timelock to the parameter change
 742 |      function setLiquidationPair(address _liquidationPair) external onlyOwner {
 743 |          if (address(_liquidationPair) == address(0)) revert LPZeroAddress();
 745 |          liquidationPair = _liquidationPair;
 747 |          emit LiquidationPairSet(address(this), address(_liquidationPair));
 748 |      }

     |  // @audit-issue Add a timelock to the parameter change
 753 |  function setYieldFeePercentage(uint32 _yieldFeePercentage) external onlyOwner {
 754 |      _setYieldFeePercentage(_yieldFeePercentage);
 755 |  }

     |  // @audit-issue Add a timelock to the parameter change
 759 |  function setYieldFeeRecipient(address _yieldFeeRecipient) external onlyOwner {
 760 |      _setYieldFeeRecipient(_yieldFeeRecipient);
 761 |  }
```

*GitHub* : [735-737](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L735-L737), [742-748](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L742-L748), [753-755](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L753-L755), [759-761](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L759-L761)

### [N-24]<a name="n-24"></a> Custom error has no error details

Consider adding parameters to the error to indicate which user or values caused the failure

*There are 14 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 182 |  error YieldVaultZeroAddress();

 185 |  error OwnerZeroAddress();

 188 |  error WithdrawZeroAssets();

 191 |  error BurnZeroShares();

 194 |  error DepositZeroAssets();

 197 |  error MintZeroShares();

 200 |  error ZeroTotalAssets();

 203 |  error LPZeroAddress();

 206 |  error SweepZeroAssets();

 209 |  error LiquidationAmountOutZero();
```

*GitHub* : [182](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L182), [185](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L185), [188](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L188), [191](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L191), [194](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L194), [197](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L197), [200](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L200), [203](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L203), [206](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L206), [209](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L209)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

  33 |  error TwabControllerZeroAddress();
```

*GitHub* : [33](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L33)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

  34 |  error PrizePoolZeroAddress();

  37 |  error ClaimerZeroAddress();

  40 |  error ClaimRecipientZeroAddress();
```

*GitHub* : [34](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L34), [37](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L37), [40](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L40)

### [N-25]<a name="n-25"></a> Duplicate `require()`/`revert()` checks should be refactored to a modifier or function

The compiler will inline the function, which will avoid `JUMP` instructions usually associated with functions.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Duplicates of this conditional revert statement were detected
 612 |  if (_shares == 0) revert MintZeroShares();
  :  |
     |  // @audit-issue First seen at pt-v5-vault/src/PrizeVault.sol:612
 844 |  if (_shares == 0) revert MintZeroShares();
```

*GitHub* : [844](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L844)

### [N-26]<a name="n-26"></a> Events are missing sender information

When an action is triggered based on a user's action, not being able to filter based on who triggered the action makes event processing a lot more cumbersome. Including the `msg.sender` the events of these types of action will make events much more useful to end users, especially when `msg.sender` is not `tx.origin`.

*There are 11 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider adding msg.sender as a parameter
 562 |  emit Sponsor(_owner, _assets, _shares);

     |  // @audit-issue Consider adding msg.sender as a parameter
 747 |  emit LiquidationPairSet(address(this), address(_liquidationPair));

     |  // @audit-issue Consider adding msg.sender as a parameter
 876 |  emit Deposit(_caller, _receiver, _assets, _shares);

     |  // @audit-issue Consider adding msg.sender as a parameter
 909 |  emit Withdraw(_caller, _receiver, _owner, _assets, _shares);

     |  // @audit-issue Consider adding msg.sender as a parameter
 952 |  emit YieldFeePercentageSet(_yieldFeePercentage);

     |  // @audit-issue Consider adding msg.sender as a parameter
 960 |  emit YieldFeeRecipientSet(_yieldFeeRecipient);
```

*GitHub* : [562](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L562), [747](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L747), [876](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L876), [909](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L909), [952](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L952), [960](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L960)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider adding msg.sender as a parameter
 123 |  emit NewPrizeVault(
 124 |      _vault,
 125 |      _yieldVault,
 126 |      _prizePool,
 127 |      _name,
 128 |      _symbol
 129 |  );
```

*GitHub* : [123-129](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L123-L129)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Consider adding msg.sender as a parameter
  78 |  emit Transfer(address(0), _receiver, _amount);

     |  // @audit-issue Consider adding msg.sender as a parameter
  89 |  emit Transfer(_owner, address(0), _amount);

     |  // @audit-issue Consider adding msg.sender as a parameter
 102 |  emit Transfer(_from, _to, _amount);
```

*GitHub* : [78](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L78), [89](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L89), [102](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L102)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider adding msg.sender as a parameter
 131 |  emit ClaimerSet(_claimer);
```

*GitHub* : [131](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L131)

### [N-27]<a name="n-27"></a> Events that mark critical parameter changes should contain both the old and the new value

This should especially be done if the new value is not required to be different from the old value

*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info setter/update
 742 |  function setLiquidationPair(address _liquidationPair) external onlyOwner {
  :  |
     |      // @audit-issue Consider including 'old' parameters in emit
 747 |      emit LiquidationPairSet(address(this), address(_liquidationPair));

     |  // @audit-info setter/update
 947 |  function _setYieldFeePercentage(uint32 _yieldFeePercentage) internal {
  :  |
     |      // @audit-issue Consider including 'old' parameters in emit
 952 |      emit YieldFeePercentageSet(_yieldFeePercentage);

     |  // @audit-info setter/update
 958 |  function _setYieldFeeRecipient(address _yieldFeeRecipient) internal {
  :  |
     |      // @audit-issue Consider including 'old' parameters in emit
 960 |      emit YieldFeeRecipientSet(_yieldFeeRecipient);
```

*GitHub* : [747](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L747), [952](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L952), [960](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L960)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-info setter/update
 128 |  function _setClaimer(address _claimer) internal {
  :  |
     |      // @audit-issue Consider including 'old' parameters in emit
 131 |      emit ClaimerSet(_claimer);
```

*GitHub* : [131](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L131)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-info setter/update
  29 |  function setHooks(VaultHooks calldata hooks) external {
  :  |
     |      // @audit-issue Consider including 'old' parameters in emit
  31 |      emit SetHooks(msg.sender, hooks);
```

*GitHub* : [31](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L31)

### [N-28]<a name="n-28"></a> Function ordering does not follow the Solidity style guide

According to the [Solidity style guide](https://docs.soliditylang.org/en/v0.8.17/style-guide.html#order-of-functions), functions should be laid out in the following order :`constructor()`, `receive()`, `fallback()`, `external`, `public`, `internal`, `private`, but the cases below do not follow this pattern.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Contract node order has style violations; recommended order is:
     |  // constructor ()
     |  // external asset()
     |  // external deposit()
     |  // external mint()
     |  // external withdraw()
     |  // external redeem()
     |  // external depositWithPermit()
     |  // external sponsor()
     |  // external currentYieldBuffer()
     |  // external claimYieldFeeShares()
     |  // external verifyTokensIn()
     |  // external targetOf()
     |  // external isLiquidationPair()
     |  // external setClaimer()
     |  // external setLiquidationPair()
     |  // external setYieldFeePercentage()
     |  // external setYieldFeeRecipient()
     |  // public decimals()
     |  // public totalAssets()
     |  // public convertToShares()
     |  // public convertToAssets()
     |  // public maxDeposit()
     |  // public maxMint()
     |  // public maxWithdraw()
     |  // public maxRedeem()
     |  // public previewDeposit()
     |  // public previewMint()
     |  // public previewWithdraw()
     |  // public previewRedeem()
     |  // public totalDebt()
     |  // public totalYieldBalance()
     |  // public availableYieldBalance()
     |  // public liquidatableBalanceOf()
     |  // public transferTokensOut()
     |  // internal _tryGetAssetDecimals()
     |  // internal _totalDebt()
     |  // internal _twabSupplyLimit()
     |  // internal _totalYieldBalance()
     |  // internal _availableYieldBalance()
     |  // internal _depositAndMint()
     |  // internal _burnAndWithdraw()
     |  // internal _maxYieldVaultWithdraw()
     |  // internal _withdraw()
     |  // internal _setYieldFeePercentage()
     |  // internal _setYieldFeeRecipient()
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
  :  |
     |      // @audit-issue external asset() should be above public decimals()
 329 |      function asset() external view returns (address) {
  :  |
     |      // @audit-issue external deposit() should be above public previewRedeem()
 475 |      function deposit(uint256 _assets, address _receiver) external returns (uint256) {
  :  |
     |      // @audit-issue external currentYieldBuffer() should be above public availableYieldBalance()
 597 |      function currentYieldBuffer() external view returns (uint256) {
  :  |
     |      // @audit-issue external verifyTokensIn() should be above public transferTokensOut()
 703 |      function verifyTokensIn(
 704 |          address _tokenIn,
 705 |          uint256 _amountIn,
 706 |          bytes calldata
 707 |      ) external onlyLiquidationPair {
```

*GitHub* : [329](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L329), [475](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L475), [597](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L597), [703-707](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L703-L707)

### [N-29]<a name="n-29"></a> High cyclomatic complexity

Cyclomatic complexity is a quantitative measure of the number of linearly independent paths through a program's source code:
                
| Cyclomatic Complexity | Interpretation | Recommendation |
| - | - | - |
| 1..9 | 🟢 Low complexity | Acceptable |
| 10..19 | 🟡 Moderate complexity | Careful testing and documentation |
| 20..29 | 🟠 High complexity | Candidate for refactoring |
| 30+ | ⛔ Very high complexity | At high risk of errors |

The following functions have a moderate or higher complexity i.e. 10 or more decision points. Consider breaking down these functions into more manageable units, by splitting things into utility functions, by reducing nesting, and by using early returns.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue This function has a cyclomatic complexity of 13
 659 |      function transferTokensOut(
 660 |          address,
 661 |          address _receiver,
 662 |          address _tokenOut,
 663 |          uint256 _amountOut
 664 |      ) public virtual onlyLiquidationPair returns (bytes memory) {
 665 |          if (_amountOut == 0) revert LiquidationAmountOutZero();
 667 |          uint256 _availableYield = availableYieldBalance();
 668 |          uint32 _yieldFeePercentage = yieldFeePercentage;
 670 |          // Determine the proportional yield fee based on the amount being liquidated:
 671 |          uint256 _yieldFee;
 672 |          if (_yieldFeePercentage != 0) {
 673 |              // The yield fee is calculated as a portion of the total yield being consumed, such that 
 674 |              // `total = amountOut + yieldFee` and `yieldFee / total = yieldFeePercentage`. 
 675 |              _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;
 676 |          }
 678 |          // Ensure total liquidation amount does not exceed the available yield balance:
 679 |          if (_amountOut + _yieldFee > _availableYield) {
 680 |              revert LiquidationExceedsAvailable(_amountOut + _yieldFee, _availableYield);
 681 |          }
 683 |          // Increase yield fee balance:
 684 |          if (_yieldFee > 0) {
 685 |              yieldFeeBalance += _yieldFee;
 686 |          }
 688 |          // Mint or withdraw amountOut to `_receiver`:
 689 |          if (_tokenOut == address(_asset)) {
 690 |              _withdraw(_receiver, _amountOut);            
 691 |          } else if (_tokenOut == address(this)) {
 692 |              _mint(_receiver, _amountOut);
 693 |          } else {
 694 |              revert LiquidationTokenOutNotSupported(_tokenOut);
 695 |          }
 697 |          emit TransferYieldOut(msg.sender, _tokenOut, _receiver, _amountOut, _yieldFee);
 699 |          return "";
 700 |      }
```

*GitHub* : [659-700](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L659-L700)

### [N-30]<a name="n-30"></a> Imports should be organized more systematically

The contract's interface should be imported first, followed by each of the interfaces it uses, followed by all other files. The examples below do not follow this layout.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Import contract interface > other interfaces > project files > external files
   5 |  import { SafeERC20, IERC20Permit } from "openzeppelin/token/ERC20/utils/SafeERC20.sol";

     |  // @audit-issue Import contract interface > other interfaces > project files > external files
   6 |  import { ERC20, IERC20, IERC20Metadata } from "openzeppelin/token/ERC20/ERC20.sol";
```

*GitHub* : [5](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L5), [6](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L6)

### [N-31]<a name="n-31"></a> Large multiples of ten should use scientific notation for readability

Use a scientific notation rather than decimal literals (e.g. `1e6` instead of `1000000`, `5e3` instead of `5000`), for better code readability.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Use scientific notation (e.g. 1e18) instead
  21 |  uint24 public constant HOOK_GAS = 150_000;
```

*GitHub* : [21](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L21)

### [N-32]<a name="n-32"></a> Large or complicated code bases should implement invariant tests

This includes: large code bases, or code with lots of inline-assembly, complicated math, or complicated interactions between multiple contracts.

Invariant fuzzers such as Echidna require the test writer to come up with invariants which should not be violated under any circumstances, and the fuzzer tests various inputs and function calls to ensure that the invariants always hold.

Even code with 100% code coverage can still have bugs due to the order of the operations a user performs, and invariant fuzzers may help significantly.

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Invariant tests were not detected for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L1)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Invariant tests were not detected for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L1)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Invariant tests were not detected for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Invariant tests were not detected for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Invariant tests were not detected for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L1)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Invariant tests were not detected for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L1)

### [N-33]<a name="n-33"></a> Naming: name immutables using all-uppercase

Immutables should be in uppercase as stated [Solidity style guide](https://docs.soliditylang.org/en/latest/style-guide.html#constants).

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Names of immutable variables should be in all uppercase
 112 |  uint256 public immutable yieldBuffer;

     |  // @audit-issue Names of immutable variables should be in all uppercase
 115 |  IERC4626 public immutable yieldVault;

     |  // @audit-issue Names of immutable variables should be in all uppercase
 135 |  IERC20 private immutable _asset;

     |  // @audit-issue Names of immutable variables should be in all uppercase
 138 |  uint8 private immutable _underlyingDecimals;
```

*GitHub* : [112](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L112), [115](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L115), [135](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L135), [138](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L138)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Names of immutable variables should be in all uppercase
  26 |  TwabController public immutable twabController;
```

*GitHub* : [26](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L26)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Names of immutable variables should be in all uppercase
  24 |  PrizePool public immutable prizePool;
```

*GitHub* : [24](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L24)

### [N-34]<a name="n-34"></a> NatSpec: Contract declarations should have `@dev` tags

`@dev` is used to explain extra details to developers

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Add NatSpec @dev
  13 |  contract PrizeVaultFactory {
```

*GitHub* : [13](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L13)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Add NatSpec @dev
  13 |  abstract contract Claimable is HookManager, IClaimable {
```

*GitHub* : [13](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L13)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Add NatSpec @dev
   9 |  abstract contract HookManager {
```

*GitHub* : [9](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L9)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Add NatSpec @dev
  17 |  interface IVaultHooks {
```

*GitHub* : [17](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L17)

### [N-35]<a name="n-35"></a> NatSpec: Error definitions should have `@dev` tags

`@dev` is used to explain to developers what the error does, and the compiler interprets `///` or `/**` comments as this tag if one wasn't explicitly provided.

*There are 24 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Add NatSpec @dev
 182 |  error YieldVaultZeroAddress();

     |  // @audit-issue Add NatSpec @dev
 185 |  error OwnerZeroAddress();

     |  // @audit-issue Add NatSpec @dev
 188 |  error WithdrawZeroAssets();

     |  // @audit-issue Add NatSpec @dev
 191 |  error BurnZeroShares();

     |  // @audit-issue Add NatSpec @dev
 194 |  error DepositZeroAssets();

     |  // @audit-issue Add NatSpec @dev
 197 |  error MintZeroShares();

     |  // @audit-issue Add NatSpec @dev
 200 |  error ZeroTotalAssets();

     |  // @audit-issue Add NatSpec @dev
 203 |  error LPZeroAddress();

     |  // @audit-issue Add NatSpec @dev
 206 |  error SweepZeroAssets();

     |  // @audit-issue Add NatSpec @dev
 209 |  error LiquidationAmountOutZero();

     |  // @audit-issue Add NatSpec @dev
 214 |  error CallerNotLP(address caller, address liquidationPair);

     |  // @audit-issue Add NatSpec @dev
 219 |  error CallerNotYieldFeeRecipient(address caller, address yieldFeeRecipient);

     |  // @audit-issue Add NatSpec @dev
 224 |  error PermitCallerNotOwner(address caller, address owner);

     |  // @audit-issue Add NatSpec @dev
 229 |  error YieldFeePercentageExceedsMax(uint256 yieldFeePercentage, uint256 maxYieldFeePercentage);

     |  // @audit-issue Add NatSpec @dev
 234 |  error SharesExceedsYieldFeeBalance(uint256 shares, uint256 yieldFeeBalance);

     |  // @audit-issue Add NatSpec @dev
 239 |  error LiquidationTokenInNotPrizeToken(address tokenIn, address prizeToken);

     |  // @audit-issue Add NatSpec @dev
 243 |  error LiquidationTokenOutNotSupported(address tokenOut);

     |  // @audit-issue Add NatSpec @dev
 248 |  error LiquidationExceedsAvailable(uint256 totalToWithdraw, uint256 availableYield);

     |  // @audit-issue Add NatSpec @dev
 253 |  error LossyDeposit(uint256 totalAssets, uint256 totalSupply);
```

*GitHub* : [182](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L182), [185](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L185), [188](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L188), [191](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L191), [194](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L194), [197](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L197), [200](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L200), [203](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L203), [206](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L206), [209](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L209), [214](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L214), [219](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L219), [224](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L224), [229](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L229), [234](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L234), [239](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L239), [243](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L243), [248](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L248), [253](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L253)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Add NatSpec @dev
  33 |  error TwabControllerZeroAddress();
```

*GitHub* : [33](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L33)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Add NatSpec @dev
  34 |  error PrizePoolZeroAddress();

     |  // @audit-issue Add NatSpec @dev
  37 |  error ClaimerZeroAddress();

     |  // @audit-issue Add NatSpec @dev
  40 |  error ClaimRecipientZeroAddress();

     |  // @audit-issue Add NatSpec @dev
  45 |  error CallerNotClaimer(address caller, address claimer);
```

*GitHub* : [34](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L34), [37](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L37), [40](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L40), [45](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L45)

### [N-36]<a name="n-36"></a> NatSpec: Event definitions should have `@dev` tags

`@dev` is used to explain to developers what the event does, as per [NatSpec Format](https://docs.soliditylang.org/en/latest/natspec-format.html#tags).

*There are 7 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Add NatSpec @dev
 146 |  event YieldFeeRecipientSet(address indexed yieldFeeRecipient);

     |  // @audit-issue Add NatSpec @dev
 150 |  event YieldFeePercentageSet(uint256 yieldFeePercentage);

     |  // @audit-issue Add NatSpec @dev
 156 |  event Sponsor(address indexed caller, uint256 assets, uint256 shares);

     |  // @audit-issue Add NatSpec @dev
 164 |  event TransferYieldOut(

     |  // @audit-issue Add NatSpec @dev
 175 |  event ClaimYieldFeeShares(address indexed recipient, uint256 shares);
```

*GitHub* : [146](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L146), [150](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L150), [156](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L156), [164](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L164), [175](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L175)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Add NatSpec @dev
  25 |  event NewPrizeVault(
```

*GitHub* : [25](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L25)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Add NatSpec @dev
  14 |  event SetHooks(address indexed account, VaultHooks hooks);
```

*GitHub* : [14](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L14)

### [N-37]<a name="n-37"></a> NatSpec: Function `@param` is missing

Documentation of all function parameters improves code readability.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Missing NatSpec @param for parameter 3 contract TwabController twabController_
  45 |  TwabController twabController_
```

*GitHub* : [45](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L45)

### [N-38]<a name="n-38"></a> NatSpec: Function definitions should have `@dev` tags

`@dev` is used to explain to developers what the function does, as per [NatSpec Format](https://docs.soliditylang.org/en/latest/natspec-format.html#tags).

*There are 29 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Add NatSpec @dev
 289 |  constructor(
 290 |      string memory name_,
 291 |      string memory symbol_,
 292 |      IERC4626 yieldVault_,
 293 |      PrizePool prizePool_,
 294 |      address claimer_,
 295 |      address yieldFeeRecipient_,
 296 |      uint32 yieldFeePercentage_,
 297 |      uint256 yieldBuffer_,
 298 |      address owner_
 299 |  ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {

     |  // @audit-issue Add NatSpec @dev
 320 |  function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {

     |  // @audit-issue Add NatSpec @dev
 329 |  function asset() external view returns (address) {

     |  // @audit-issue Add NatSpec @dev
 341 |  function convertToShares(uint256 _assets) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 355 |  function convertToAssets(uint256 _shares) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 441 |  function previewDeposit(uint256 _assets) public pure returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 447 |  function previewMint(uint256 _shares) public pure returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 470 |  function previewRedeem(uint256 _shares) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 475 |  function deposit(uint256 _assets, address _receiver) external returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 482 |  function mint(uint256 _shares, address _receiver) external returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 489 |  function withdraw(
 490 |      uint256 _assets,
 491 |      address _receiver,
 492 |      address _owner
 493 |  ) external returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 500 |  function redeem(
 501 |      uint256 _shares,
 502 |      address _receiver,
 503 |      address _owner
 504 |  ) external returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 573 |  function totalDebt() public view returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 597 |  function currentYieldBuffer() external view returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 703 |  function verifyTokensIn(
 704 |      address _tokenIn,
 705 |      uint256 _amountIn,
 706 |      bytes calldata
 707 |  ) external onlyLiquidationPair {

     |  // @audit-issue Add NatSpec @dev
 717 |  function targetOf(address) external view returns (address) {

     |  // @audit-issue Add NatSpec @dev
 722 |  function isLiquidationPair(
 723 |      address _tokenOut,
 724 |      address _liquidationPair
 725 |  ) external view returns (bool) {

     |  // @audit-issue Add NatSpec @dev
 735 |  function setClaimer(address _claimer) external onlyOwner {

     |  // @audit-issue Add NatSpec @dev
 759 |  function setYieldFeeRecipient(address _yieldFeeRecipient) external onlyOwner {

     |  // @audit-issue Add NatSpec @dev
 808 |  function _totalYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal pure returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
 928 |  function _withdraw(address _receiver, uint256 _assets) internal {
```

*GitHub* : [289-299](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L289-L299), [320](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L320), [329](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L329), [341](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L341), [355](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L355), [441](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L441), [447](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L447), [470](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L470), [475](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L475), [482](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L482), [489-493](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L489-L493), [500-504](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L500-L504), [573](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L573), [597](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L597), [703-707](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L703-L707), [717](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L717), [722-725](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L722-L725), [735](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L735), [759](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L759), [808](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L808), [928](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L928)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Add NatSpec @dev
 136 |  function totalVaults() external view returns (uint256) {
```

*GitHub* : [136](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L136)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Add NatSpec @dev
  42 |  constructor(
  43 |      string memory name_,
  44 |      string memory symbol_,
  45 |      TwabController twabController_
  46 |  ) ERC20(name_, symbol_) ERC20Permit(name_) {

     |  // @audit-issue Add NatSpec @dev
  56 |  function balanceOf(
  57 |      address _account
  58 |  ) public view virtual override(ERC20) returns (uint256) {

     |  // @audit-issue Add NatSpec @dev
  63 |  function totalSupply() public view virtual override(ERC20) returns (uint256) {
```

*GitHub* : [42-46](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L42-L46), [56-58](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L56-L58), [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L63)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Add NatSpec @dev
  64 |  constructor(PrizePool prizePool_, address claimer_) {
```

*GitHub* : [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L64)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Add NatSpec @dev
  22 |  function getHooks(address account) external view returns (VaultHooks memory) {
```

*GitHub* : [22](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L22)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Add NatSpec @dev
  26 |  function beforeClaimPrize(
  27 |      address winner,
  28 |      uint8 tier,
  29 |      uint32 prizeIndex,
  30 |      uint96 reward,
  31 |      address rewardRecipient
  32 |  ) external returns (address);

     |  // @audit-issue Add NatSpec @dev
  40 |  function afterClaimPrize(
  41 |      address winner,
  42 |      uint8 tier,
  43 |      uint32 prizeIndex,
  44 |      uint256 prize,
  45 |      address recipient
  46 |  ) external;
```

*GitHub* : [26-32](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L26-L32), [40-46](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L40-L46)

### [N-39]<a name="n-39"></a> NatSpec: Function definitions should have `@notice` tags

`@notice` is used to explain to end users what the function does, and the compiler interprets `///` or `/**` comments as this tag if one wasn't explicitly provided.

*There are 25 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Add NatSpec @notice
 320 |  function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {

     |  // @audit-issue Add NatSpec @notice
 329 |  function asset() external view returns (address) {

     |  // @audit-issue Add NatSpec @notice
 336 |  function totalAssets() public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 341 |  function convertToShares(uint256 _assets) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 355 |  function convertToAssets(uint256 _shares) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 374 |  function maxDeposit(address) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 397 |  function maxMint(address _owner) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 404 |  function maxWithdraw(address _owner) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 415 |  function maxRedeem(address _owner) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 441 |  function previewDeposit(uint256 _assets) public pure returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 447 |  function previewMint(uint256 _shares) public pure returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 454 |  function previewWithdraw(uint256 _assets) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 470 |  function previewRedeem(uint256 _shares) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 475 |  function deposit(uint256 _assets, address _receiver) external returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 482 |  function mint(uint256 _shares, address _receiver) external returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 489 |  function withdraw(
 490 |      uint256 _assets,
 491 |      address _receiver,
 492 |      address _owner
 493 |  ) external returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 500 |  function redeem(
 501 |      uint256 _shares,
 502 |      address _receiver,
 503 |      address _owner
 504 |  ) external returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 631 |  function liquidatableBalanceOf(address _tokenOut) public view returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
 659 |  function transferTokensOut(
 660 |      address,
 661 |      address _receiver,
 662 |      address _tokenOut,
 663 |      uint256 _amountOut
 664 |  ) public virtual onlyLiquidationPair returns (bytes memory) {

     |  // @audit-issue Add NatSpec @notice
 703 |  function verifyTokensIn(
 704 |      address _tokenIn,
 705 |      uint256 _amountIn,
 706 |      bytes calldata
 707 |  ) external onlyLiquidationPair {

     |  // @audit-issue Add NatSpec @notice
 717 |  function targetOf(address) external view returns (address) {

     |  // @audit-issue Add NatSpec @notice
 722 |  function isLiquidationPair(
 723 |      address _tokenOut,
 724 |      address _liquidationPair
 725 |  ) external view returns (bool) {
```

*GitHub* : [320](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L320), [329](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L329), [336](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L336), [341](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L341), [355](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L355), [374](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L374), [397](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L397), [404](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L404), [415](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L415), [441](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L441), [447](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L447), [454](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L454), [470](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L470), [475](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L475), [482](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L482), [489-493](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L489-L493), [500-504](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L500-L504), [631](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L631), [659-664](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L659-L664), [703-707](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L703-L707), [717](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L717), [722-725](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L722-L725)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Add NatSpec @notice
  56 |  function balanceOf(
  57 |      address _account
  58 |  ) public view virtual override(ERC20) returns (uint256) {

     |  // @audit-issue Add NatSpec @notice
  63 |  function totalSupply() public view virtual override(ERC20) returns (uint256) {
```

*GitHub* : [56-58](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L56-L58), [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L63)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Add NatSpec @notice
  76 |  function claimPrize(
  77 |      address _winner,
  78 |      uint8 _tier,
  79 |      uint32 _prizeIndex,
  80 |      uint96 _reward,
  81 |      address _rewardRecipient
  82 |  ) external onlyClaimer returns (uint256) {
```

*GitHub* : [76-82](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L76-L82)

### [N-40]<a name="n-40"></a> NatSpec: Modifier definitions should have `@dev` tags

`@dev` is used to explain to developers what the modifier does, and the compiler interprets `///` or `/**` comments as this tag if one wasn't explicitly provided.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Add NatSpec @dev
 260 |  modifier onlyLiquidationPair() {
 261 |      if (msg.sender != liquidationPair) {
 262 |          revert CallerNotLP(msg.sender, liquidationPair);
 263 |      }
 264 |      _;
 265 |  }

     |  // @audit-issue Add NatSpec @dev
 268 |  modifier onlyYieldFeeRecipient() {
 269 |      if (msg.sender != yieldFeeRecipient) {
 270 |          revert CallerNotYieldFeeRecipient(msg.sender, yieldFeeRecipient);
 271 |      }
 272 |      _;
 273 |  }
```

*GitHub* : [260-265](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L260-L265), [268-273](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L268-L273)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Add NatSpec @dev
  52 |  modifier onlyClaimer() {
  53 |      if (msg.sender != claimer) revert CallerNotClaimer(msg.sender, claimer);
  54 |      _;
  55 |  }
```

*GitHub* : [52-55](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L52-L55)

### [N-41]<a name="n-41"></a> NatSpec: Non-public state variable declarations should use `@dev` tags

As per [Solidity NatSpec](https://docs.soliditylang.org/en/latest/natspec-format.html#tags). Note: public and non-public state variables should have a @dev tag. Only public state variables should have a @notice tag.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Add NatSpec @dev documentation
 135 |  IERC20 private immutable _asset;

     |  // @audit-issue Add NatSpec @dev documentation
 138 |  uint8 private immutable _underlyingDecimals;
```

*GitHub* : [135](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L135), [138](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L138)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Add NatSpec @dev documentation
  17 |  mapping(address => VaultHooks) internal _hooks;
```

*GitHub* : [17](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L17)

### [N-42]<a name="n-42"></a> NatSpec: missing from file

As per the [Solidity Style Guide](https://docs.soliditylang.org/en/v0.8.22/style-guide.html#natspec):

        >  They are written with a triple slash (///) or a double asterisk block (/** ... */) and they should be used directly above function declarations or statements.

        Files with no NatSpec documentation are more difficult to use and review.
        

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Add NatSpec comments to this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L1)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Add NatSpec comments to this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L1)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Add NatSpec comments to this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Add NatSpec comments to this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Add NatSpec comments to this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L1)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Add NatSpec comments to this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L1)

### [N-43]<a name="n-43"></a> Parameter change does not emit event

Events help non-contract tools to track changes, and events prevent users from being surprised by changes

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider emitting an event documenting the parameter change
 735 |  function setClaimer(address _claimer) external onlyOwner {

     |  // @audit-issue Consider emitting an event documenting the parameter change
 753 |  function setYieldFeePercentage(uint32 _yieldFeePercentage) external onlyOwner {

     |  // @audit-issue Consider emitting an event documenting the parameter change
 759 |  function setYieldFeeRecipient(address _yieldFeeRecipient) external onlyOwner {
```

*GitHub* : [735](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L735), [753](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L753), [759](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L759)

### [N-44]<a name="n-44"></a> Redundant `else` block

One level of nesting can be removed by not having an else block when the if-block returns.

*There are 7 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue The else clause is unnecessary
 344 |  if (_totalAssets >= totalDebt_) {
 345 |      return _assets;
 346 |  } else {
 347 |      // If the vault controls less assets than what has been deposited a share will be worth a
 348 |      // proportional amount of the total assets. This can happen due to fees, slippage, or loss
 349 |      // of funds in the underlying yield vault.
 350 |      return _assets.mulDiv(totalDebt_, _totalAssets, Math.Rounding.Down);
 351 |  }

     |  // @audit-issue The else clause is unnecessary
 358 |  if (_totalAssets >= totalDebt_) {
 359 |      return _shares;
 360 |  } else {
 361 |      // If the vault controls less assets than what has been deposited a share will be worth a
 362 |      // proportional amount of the total assets. This can happen due to fees, slippage, or loss
 363 |      // of funds in the underlying yield vault.
 364 |      return _shares.mulDiv(_totalAssets, totalDebt_, Math.Rounding.Down);
 365 |  }

     |  // @audit-issue The else clause is unnecessary
 384 |  if (_latentBalance >= _maxYieldVaultDeposit) {
 385 |      return 0;
 386 |  } else {
 387 |      unchecked {
 388 |          _maxDeposit = _maxYieldVaultDeposit - _latentBalance;
 389 |      }
 390 |      return twabSupplyLimit_ < _maxDeposit ? twabSupplyLimit_ : _maxDeposit;
 391 |  }

     |  // @audit-issue The else clause is unnecessary
 425 |  if (_totalAssets >= totalDebt_) {
 426 |      return _maxWithdraw;
 427 |  } else {
 428 |      // Convert to shares while rounding up. Since 1 asset is guaranteed to be worth more than
 429 |      // 1 share and any upwards rounding will not exceed 1 share, we can be sure that when the
 430 |      // shares are converted back to assets (rounding down) the resulting asset value won't
 431 |      // exceed `_maxWithdraw`.
 432 |      uint256 _maxScaledRedeem = _maxWithdraw.mulDiv(totalDebt_, _totalAssets, Math.Rounding.Up);
 433 |      return _maxScaledRedeem >= _ownerShares ? _ownerShares : _maxScaledRedeem;
 434 |  }

     |  // @audit-issue The else clause is unnecessary
 461 |  if (_totalAssets >= totalDebt_) {
 462 |      return _assets;
 463 |  } else {
 464 |      // Follows the inverse conversion of `convertToAssets`
 465 |      return _assets.mulDiv(totalDebt_, _totalAssets, Math.Rounding.Up);
 466 |  }

     |  // @audit-issue The else clause is unnecessary
 600 |  if (totalYieldBalance_ >= _yieldBuffer) {
 601 |      return _yieldBuffer;
 602 |  } else {
 603 |      return totalYieldBalance_;
 604 |  }

     |  // @audit-issue The else clause is unnecessary
 809 |  if (totalDebt_ >= _totalAssets) {
 810 |      return 0;
 811 |  } else {
 812 |      unchecked {
 813 |          return _totalAssets - totalDebt_;
 814 |      }
 815 |  }
```

*GitHub* : [344-351](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L344-L351), [358-365](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L358-L365), [384-391](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L384-L391), [425-434](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L425-L434), [461-466](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L461-L466), [600-604](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L600-L604), [809-815](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L809-L815)

### [N-45]<a name="n-45"></a> Setters should prevent re-setting the same value

This especially problematic when the setter also emits the same value, which may be confusing to offline parsers.

*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Context
 742 |  function setLiquidationPair(address _liquidationPair) external onlyOwner {
  :  |
     |      // @audit-issue Check if `_liquidationPair` changes anything before assignment
 745 |      liquidationPair = _liquidationPair;

     |  // @audit-info Context
 947 |  function _setYieldFeePercentage(uint32 _yieldFeePercentage) internal {
  :  |
     |      // @audit-issue Check if `_yieldFeePercentage` changes anything before assignment
 951 |      yieldFeePercentage = _yieldFeePercentage;

     |  // @audit-info Context
 958 |  function _setYieldFeeRecipient(address _yieldFeeRecipient) internal {
     |      // @audit-issue Check if `_yieldFeeRecipient` changes anything before assignment
 959 |      yieldFeeRecipient = _yieldFeeRecipient;
```

*GitHub* : [745](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L745), [951](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L951), [959](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L959)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-info Context
 128 |  function _setClaimer(address _claimer) internal {
  :  |
     |      // @audit-issue Check if `_claimer` changes anything before assignment
 130 |      claimer = _claimer;
```

*GitHub* : [130](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L130)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-info Context
  29 |  function setHooks(VaultHooks calldata hooks) external {
     |      // @audit-issue Check if `hooks` changes anything before assignment
  30 |      _hooks[msg.sender] = hooks;
```

*GitHub* : [30](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L30)

### [N-46]<a name="n-46"></a> Style guide: Non-`external`/`public` function names should begin with an underscore

According to the Solidity Style Guide, Non-`external`/`public` variable and function names should begin with an [underscore](https://docs.soliditylang.org/en/latest/style-guide.html#underscore-prefix-for-non-external-functions-and-variables).

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Prefix function name with an `_` (underscore)
  64 |  constructor(PrizePool prizePool_, address claimer_) {
```

*GitHub* : [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L64)

### [N-47]<a name="n-47"></a> Style guide: State and local variables should be named using lowerCamelCase

The Solidity style guide [says](https://docs.soliditylang.org/en/latest/style-guide.html#local-and-state-variable-names) to use mixedCase for local and state variable names. Note that while OpenZeppelin may not follow this advice, it still is the recommended way of naming variables.

*There are 45 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Use lowerCamelCase style in name `asset_`
 303 |  IERC20 asset_ = IERC20(yieldVault_.asset());

     |  // @audit-issue Use lowerCamelCase style in name `totalDebt_`
 342 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Use lowerCamelCase style in name `_totalAssets`
 343 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Use lowerCamelCase style in name `totalDebt_`
 356 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Use lowerCamelCase style in name `_totalAssets`
 357 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Use lowerCamelCase style in name `_totalSupply`
 375 |  uint256 _totalSupply = totalSupply();

     |  // @audit-issue Use lowerCamelCase style in name `totalDebt_`
 376 |  uint256 totalDebt_ = _totalDebt(_totalSupply);

     |  // @audit-issue Use lowerCamelCase style in name `twabSupplyLimit_`
 380 |  uint256 twabSupplyLimit_ = _twabSupplyLimit(_totalSupply);

     |  // @audit-issue Use lowerCamelCase style in name `_maxDeposit`
 381 |  uint256 _maxDeposit;

     |  // @audit-issue Use lowerCamelCase style in name `_latentBalance`
 382 |  uint256 _latentBalance = _asset.balanceOf(address(this));

     |  // @audit-issue Use lowerCamelCase style in name `_maxYieldVaultDeposit`
 383 |  uint256 _maxYieldVaultDeposit = yieldVault.maxDeposit(address(this));

     |  // @audit-issue Use lowerCamelCase style in name `_maxWithdraw`
 405 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Use lowerCamelCase style in name `_ownerAssets`
 408 |  uint256 _ownerAssets = convertToAssets(balanceOf(_owner));

     |  // @audit-issue Use lowerCamelCase style in name `_maxWithdraw`
 416 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Use lowerCamelCase style in name `_ownerShares`
 417 |  uint256 _ownerShares = balanceOf(_owner);

     |  // @audit-issue Use lowerCamelCase style in name `_totalAssets`
 423 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Use lowerCamelCase style in name `totalDebt_`
 424 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Use lowerCamelCase style in name `_maxScaledRedeem`
 432 |  uint256 _maxScaledRedeem = _maxWithdraw.mulDiv(totalDebt_, _totalAssets, Math.Rounding.Up);

     |  // @audit-issue Use lowerCamelCase style in name `_totalAssets`
 455 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Use lowerCamelCase style in name `totalDebt_`
 460 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Use lowerCamelCase style in name `_shares`
 476 |  uint256 _shares = previewDeposit(_assets);

     |  // @audit-issue Use lowerCamelCase style in name `_assets`
 483 |  uint256 _assets = previewMint(_shares);

     |  // @audit-issue Use lowerCamelCase style in name `_shares`
 494 |  uint256 _shares = previewWithdraw(_assets);

     |  // @audit-issue Use lowerCamelCase style in name `_assets`
 505 |  uint256 _assets = previewRedeem(_shares);

     |  // @audit-issue Use lowerCamelCase style in name `_shares`
 543 |  uint256 _shares = previewDeposit(_assets);

     |  // @audit-issue Use lowerCamelCase style in name `_owner`
 553 |  address _owner = msg.sender;

     |  // @audit-issue Use lowerCamelCase style in name `_shares`
 555 |  uint256 _shares = previewDeposit(_assets);

     |  // @audit-issue Use lowerCamelCase style in name `totalYieldBalance_`
 598 |  uint256 totalYieldBalance_ = _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Use lowerCamelCase style in name `_yieldBuffer`
 599 |  uint256 _yieldBuffer = yieldBuffer;

     |  // @audit-issue Use lowerCamelCase style in name `_yieldFeeBalance`
 614 |  uint256 _yieldFeeBalance = yieldFeeBalance;

     |  // @audit-issue Use lowerCamelCase style in name `_totalSupply`
 632 |  uint256 _totalSupply = totalSupply();

     |  // @audit-issue Use lowerCamelCase style in name `_maxAmountOut`
 633 |  uint256 _maxAmountOut;

     |  // @audit-issue Use lowerCamelCase style in name `_liquidYield`
 647 |  uint256 _liquidYield = 

     |  // @audit-issue Use lowerCamelCase style in name `_availableYield`
 667 |  uint256 _availableYield = availableYieldBalance();

     |  // @audit-issue Use lowerCamelCase style in name `_yieldFeePercentage`
 668 |  uint32 _yieldFeePercentage = yieldFeePercentage;

     |  // @audit-issue Use lowerCamelCase style in name `_yieldFee`
 671 |  uint256 _yieldFee;

     |  // @audit-issue Use lowerCamelCase style in name `_prizeToken`
 708 |  address _prizeToken = address(prizePool.prizeToken());

     |  // @audit-issue Use lowerCamelCase style in name `totalYieldBalance_`
 824 |  uint256 totalYieldBalance_ = _totalYieldBalance(_totalAssets, totalDebt_);

     |  // @audit-issue Use lowerCamelCase style in name `_yieldBuffer`
 825 |  uint256 _yieldBuffer = yieldBuffer;

     |  // @audit-issue Use lowerCamelCase style in name `_assetsWithDust`
 861 |  uint256 _assetsWithDust = _asset.balanceOf(address(this));

     |  // @audit-issue Use lowerCamelCase style in name `_yieldVaultShares`
 865 |  uint256 _yieldVaultShares = yieldVault.previewDeposit(_assetsWithDust);

     |  // @audit-issue Use lowerCamelCase style in name `_assetsUsed`
 866 |  uint256 _assetsUsed = yieldVault.mint(_yieldVaultShares, address(this));

     |  // @audit-issue Use lowerCamelCase style in name `_latentAssets`
 931 |  uint256 _latentAssets = _asset.balanceOf(address(this));

     |  // @audit-issue Use lowerCamelCase style in name `_yieldVaultShares`
 934 |  uint256 _yieldVaultShares = yieldVault.previewWithdraw(_assets - _latentAssets);
```

*GitHub* : [303](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L303), [342](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L342), [343](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L343), [356](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L356), [357](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L357), [375](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L375), [376](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L376), [380](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L380), [381](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L381), [382](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L382), [383](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L383), [405](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L405), [408](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L408), [416](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L416), [417](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L417), [423](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L423), [424](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L424), [432](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L432), [455](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L455), [460](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L460), [476](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L476), [483](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L483), [494](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L494), [505](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L505), [543](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L543), [553](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L553), [555](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L555), [598](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L598), [599](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L599), [614](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L614), [632](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L632), [633](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L633), [647](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L647), [667](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L667), [668](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L668), [671](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L671), [708](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L708), [824](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L824), [825](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L825), [861](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L861), [865](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L865), [866](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L866), [931](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L931), [934](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L934)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Use lowerCamelCase style in name `_vault`
 102 |  PrizeVault _vault = new PrizeVault{
```

*GitHub* : [102](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L102)

### [N-48]<a name="n-48"></a> Style guide: Using underscore at the end of variable name

The use of underscore at the end of the variable name is uncommon and also suggests that the variable name was not completely changed. Consider refactoring `variableName_` to `variableName`.

*There are 26 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Don't use underscores at the end of variable names
 290 |  string memory name_,

     |  // @audit-issue Don't use underscores at the end of variable names
 291 |  string memory symbol_,

     |  // @audit-issue Don't use underscores at the end of variable names
 292 |  IERC4626 yieldVault_,

     |  // @audit-issue Don't use underscores at the end of variable names
 293 |  PrizePool prizePool_,

     |  // @audit-issue Don't use underscores at the end of variable names
 294 |  address claimer_,

     |  // @audit-issue Don't use underscores at the end of variable names
 295 |  address yieldFeeRecipient_,

     |  // @audit-issue Don't use underscores at the end of variable names
 296 |  uint32 yieldFeePercentage_,

     |  // @audit-issue Don't use underscores at the end of variable names
 297 |  uint256 yieldBuffer_,

     |  // @audit-issue Don't use underscores at the end of variable names
 298 |  address owner_

     |  // @audit-issue Don't use underscores at the end of variable names
 303 |  IERC20 asset_ = IERC20(yieldVault_.asset());

     |  // @audit-issue Don't use underscores at the end of variable names
 342 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Don't use underscores at the end of variable names
 356 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Don't use underscores at the end of variable names
 376 |  uint256 totalDebt_ = _totalDebt(_totalSupply);

     |  // @audit-issue Don't use underscores at the end of variable names
 380 |  uint256 twabSupplyLimit_ = _twabSupplyLimit(_totalSupply);

     |  // @audit-issue Don't use underscores at the end of variable names
 424 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Don't use underscores at the end of variable names
 460 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Don't use underscores at the end of variable names
 598 |  uint256 totalYieldBalance_ = _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Don't use underscores at the end of variable names
 772 |  function _tryGetAssetDecimals(IERC20 asset_) internal view returns (bool, uint8) {

     |  // @audit-issue Don't use underscores at the end of variable names
 808 |  function _totalYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal pure returns (uint256) {

     |  // @audit-issue Don't use underscores at the end of variable names
 823 |  function _availableYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal view returns (uint256) {

     |  // @audit-issue Don't use underscores at the end of variable names
 824 |  uint256 totalYieldBalance_ = _totalYieldBalance(_totalAssets, totalDebt_);
```

*GitHub* : [290](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L290), [291](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L291), [292](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L292), [293](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L293), [294](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L294), [295](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L295), [296](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L296), [297](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L297), [298](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L298), [303](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L303), [342](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L342), [356](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L356), [376](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L376), [380](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L380), [424](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L424), [460](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L460), [598](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L598), [772](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L772), [808](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L808), [823](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L823), [824](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L824)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Don't use underscores at the end of variable names
  43 |  string memory name_,

     |  // @audit-issue Don't use underscores at the end of variable names
  44 |  string memory symbol_,

     |  // @audit-issue Don't use underscores at the end of variable names
  45 |  TwabController twabController_
```

*GitHub* : [43](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L43), [44](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L44), [45](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L45)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Don't use underscores at the end of variable names
  64 |  constructor(PrizePool prizePool_, address claimer_) {

     |  // @audit-issue Don't use underscores at the end of variable names
  64 |  constructor(PrizePool prizePool_, address claimer_) {
```

*GitHub* : [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L64), [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L64)

### [N-49]<a name="n-49"></a> Style: surround top level declarations with two blank lines

As per the [Solidity Style Guide](https://docs.soliditylang.org/en/v0.8.22/style-guide.html#blank-lines):
        
> Surround top level declarations in Solidity source with two blank lines.

Note:  this rule does not apply to `import` directives following another `import` directive.

*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Separate top-level declarations with at least two lines
   2 |  pragma solidity ^0.8.24;
   4 |  import { IERC4626 } from "openzeppelin/interfaces/IERC4626.sol";
```

*GitHub* : [2-4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L2-L4)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Separate top-level declarations with at least two lines
   2 |  pragma solidity ^0.8.24;
   4 |  import { IERC20, IERC4626 } from "openzeppelin/token/ERC20/extensions/ERC4626.sol";
```

*GitHub* : [2-4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L2-L4)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Separate top-level declarations with at least two lines
   2 |  pragma solidity ^0.8.24;
   4 |  import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";
```

*GitHub* : [2-4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L2-L4)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Separate top-level declarations with at least two lines
   2 |  pragma solidity ^0.8.24;
   4 |  import { IClaimable } from "pt-v5-claimable-interface/interfaces/IClaimable.sol";
```

*GitHub* : [2-4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L2-L4)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Separate top-level declarations with at least two lines
   2 |  pragma solidity ^0.8.0;
   4 |  import { VaultHooks } from "../interfaces/IVaultHooks.sol";
```

*GitHub* : [2-4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L2-L4)

### [N-50]<a name="n-50"></a> Syntax: place constants on left-hand side of comparisons

When writing a comparison, it is easy to accidentally use the `=` (assignment) operator. By placing constants on the left-hand side of the expression, the compiler will produce an error when an assignment has been accidentally used, thus preventing a bug.

*There are 9 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Swap left- and right-hand sides to avoid accidental assignments
 458 |  if (_totalAssets == 0) revert ZeroTotalAssets();

     |  // @audit-issue Swap left- and right-hand sides to avoid accidental assignments
 612 |  if (_shares == 0) revert MintZeroShares();

     |  // @audit-issue Swap left- and right-hand sides to avoid accidental assignments
 665 |  if (_amountOut == 0) revert LiquidationAmountOutZero();

     |  // @audit-issue Swap left- and right-hand sides to avoid accidental assignments
 672 |  if (_yieldFeePercentage != 0) {

     |  // @audit-issue Swap left- and right-hand sides to avoid accidental assignments
 776 |  if (success && encodedDecimals.length >= 32) {

     |  // @audit-issue Swap left- and right-hand sides to avoid accidental assignments
 844 |  if (_shares == 0) revert MintZeroShares();

     |  // @audit-issue Swap left- and right-hand sides to avoid accidental assignments
 845 |  if (_assets == 0) revert DepositZeroAssets();

     |  // @audit-issue Swap left- and right-hand sides to avoid accidental assignments
 894 |  if (_assets == 0) revert WithdrawZeroAssets();

     |  // @audit-issue Swap left- and right-hand sides to avoid accidental assignments
 895 |  if (_shares == 0) revert BurnZeroShares();
```

*GitHub* : [458](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L458), [612](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L612), [665](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L665), [672](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L672), [776](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L776), [844](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L844), [845](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L845), [894](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L894), [895](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L895)

### [N-51]<a name="n-51"></a> Syntax: unnecessary `override`

Starting with Solidity version [0.8.8](https://docs.soliditylang.org/en/v0.8.20/contracts.html#function-overriding), using the `override` keyword when the function solely overrides an interface function, and the function doesn't exist in multiple base contracts, is unnecessary.

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Remove `override`
 320 |  function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {
```

*GitHub* : [320](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L320)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Remove `override`
  56 |  function balanceOf(
  57 |      address _account
  58 |  ) public view virtual override(ERC20) returns (uint256) {

     |  // @audit-issue Remove `override`
  63 |  function totalSupply() public view virtual override(ERC20) returns (uint256) {

     |  // @audit-issue Remove `override`
  76 |  function _mint(address _receiver, uint256 _amount) internal virtual override {

     |  // @audit-issue Remove `override`
  87 |  function _burn(address _owner, uint256 _amount) internal virtual override {

     |  // @audit-issue Remove `override`
 100 |  function _transfer(address _from, address _to, uint256 _amount) internal virtual override {
```

*GitHub* : [56-58](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L56-L58), [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L63), [76](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L76), [87](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L87), [100](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L100)

### [N-52]<a name="n-52"></a> Unnecessary cast

Unnecessary casts can be removed.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Cast to address is redundant
 743 |  if (address(_liquidationPair) == address(0)) revert LPZeroAddress();

     |  // @audit-issue Cast to address is redundant
 747 |  emit LiquidationPairSet(address(this), address(_liquidationPair));
```

*GitHub* : [743](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L743), [747](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L747)

### [N-53]<a name="n-53"></a> Unused `error` definition

Note that there may be cases where an error superficially appears to be used, but this is only because there are multiple definitions of the error in different files. In such cases, the error definition should be moved into a separate file. The instances below are the unused definitions.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Unused by files in analysis scope
 206 |  error SweepZeroAssets();
```

*GitHub* : [206](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L206)

### [N-54]<a name="n-54"></a> Unused `function` definition

Note that there may be cases where a function superficially appears to be used, but this is only because there are multiple definitions of the function in different files. In such cases, the function definition should be moved into a separate file. The instances below are the unused definitions *within the defined scope of analysis*. It is possible these functions are used outside the scope of the analysis.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue _mint is unused by files in analysis scope
  76 |  function _mint(address _receiver, uint256 _amount) internal virtual override {

     |  // @audit-issue _burn is unused by files in analysis scope
  87 |  function _burn(address _owner, uint256 _amount) internal virtual override {

     |  // @audit-issue _transfer is unused by files in analysis scope
 100 |  function _transfer(address _from, address _to, uint256 _amount) internal virtual override {
```

*GitHub* : [76](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L76), [87](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L87), [100](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L100)

### [N-55]<a name="n-55"></a> Unused `struct` definition

Note that there may be cases where a struct superficially appears to be used, but this is only because there are multiple definitions of the struct in different files. In such cases, the struct definition should be moved into a separate file. The instances below are the unused definitions.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue VaultHooks is unused by files in analysis scope
   8 |  struct VaultHooks {
```

*GitHub* : [8](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L8)

### [N-56]<a name="n-56"></a> Unused import

Some imports are not used, consider removing them.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue TwabController is unused
  15 |  import { TwabController, SPONSORSHIP_ADDRESS } from "pt-v5-twab-controller/TwabController.sol";
```

*GitHub* : [15](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L15)

### [N-57]<a name="n-57"></a> Use a single file for system wide constants

Consider grouping all the system constants under a single file. This finding shows only the first constant for each file, for brevity.

*There are 4 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider grouping constants like this into a single file
  74 |  uint32 public constant FEE_PRECISION = 1e9;
```

*GitHub* : [74](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L74)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider grouping constants like this into a single file
  63 |  uint256 public constant YIELD_BUFFER = 1e5;
```

*GitHub* : [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L63)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Consider grouping constants like this into a single file
  26 |  TwabController public immutable twabController;
```

*GitHub* : [26](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L26)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider grouping constants like this into a single file
  21 |  uint24 public constant HOOK_GAS = 150_000;
```

*GitHub* : [21](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L21)

### [N-58]<a name="n-58"></a> Use a struct to encapsulate multiple function parameters

If a function has too many parameters, replacing them with a struct can improve code readability and maintainability, increase reusability, and reduce the likelihood of errors when passing the parameters.

*There are 7 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider replacing multiple parameters with structs
 289 |  constructor(
 290 |      string memory name_,
 291 |      string memory symbol_,
 292 |      IERC4626 yieldVault_,
 293 |      PrizePool prizePool_,
 294 |      address claimer_,
 295 |      address yieldFeeRecipient_,
 296 |      uint32 yieldFeePercentage_,
 297 |      uint256 yieldBuffer_,
 298 |      address owner_
 299 |  ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {

     |  // @audit-issue Consider replacing multiple parameters with structs
 524 |  function depositWithPermit(
 525 |      uint256 _assets,
 526 |      address _owner,
 527 |      uint256 _deadline,
 528 |      uint8 _v,
 529 |      bytes32 _r,
 530 |      bytes32 _s
 531 |  ) external returns (uint256) {

     |  // @audit-issue Consider replacing multiple parameters with structs
 887 |  function _burnAndWithdraw(
 888 |      address _caller,
 889 |      address _receiver,
 890 |      address _owner,
 891 |      uint256 _shares,
 892 |      uint256 _assets
 893 |  ) internal {
```

*GitHub* : [289-299](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L289-L299), [524-531](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L524-L531), [887-893](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L887-L893)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider replacing multiple parameters with structs
  92 |  function deployVault(
  93 |    string memory _name,
  94 |    string memory _symbol,
  95 |    IERC4626 _yieldVault,
  96 |    PrizePool _prizePool,
  97 |    address _claimer,
  98 |    address _yieldFeeRecipient,
  99 |    uint32 _yieldFeePercentage,
 100 |    address _owner
 101 |  ) external returns (PrizeVault) {
```

*GitHub* : [92-101](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L92-L101)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider replacing multiple parameters with structs
  76 |  function claimPrize(
  77 |      address _winner,
  78 |      uint8 _tier,
  79 |      uint32 _prizeIndex,
  80 |      uint96 _reward,
  81 |      address _rewardRecipient
  82 |  ) external onlyClaimer returns (uint256) {
```

*GitHub* : [76-82](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L76-L82)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue Consider replacing multiple parameters with structs
  26 |  function beforeClaimPrize(
  27 |      address winner,
  28 |      uint8 tier,
  29 |      uint32 prizeIndex,
  30 |      uint96 reward,
  31 |      address rewardRecipient
  32 |  ) external returns (address);

     |  // @audit-issue Consider replacing multiple parameters with structs
  40 |  function afterClaimPrize(
  41 |      address winner,
  42 |      uint8 tier,
  43 |      uint32 prizeIndex,
  44 |      uint256 prize,
  45 |      address recipient
  46 |  ) external;
```

*GitHub* : [26-32](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L26-L32), [40-46](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L40-L46)

### [N-59]<a name="n-59"></a> Use safePermit in place of permit

OpenZeppelin's SafePermit is designed to facilitate secure and seamless token approvals via off-chain signed messages, mitigating the risks associated with on-chain transactions. It follows the ERC-2612 standard, ensuring compatibility with various wallets and dApps, and aligning with established industry guidelines.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 540 |  IERC20Permit(address(_asset)).permit(_owner, address(this), _assets, _deadline, _v, _r, _s);
```

*GitHub* : [540](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L540)

### [N-60]<a name="n-60"></a> Use ternary expressions over `if`/`else` where possible

The code can be made more compact while also increasing readability by converting the following `if`-statements to ternaries (e.g. `foo += (x > y) ? a : b`)

*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Convert to a ternary expression
 344 |  if (_totalAssets >= totalDebt_) {
 345 |      return _assets;
 346 |  } else {
 347 |      // If the vault controls less assets than what has been deposited a share will be worth a
 348 |      // proportional amount of the total assets. This can happen due to fees, slippage, or loss
 349 |      // of funds in the underlying yield vault.
 350 |      return _assets.mulDiv(totalDebt_, _totalAssets, Math.Rounding.Down);
 351 |  }

     |  // @audit-issue Convert to a ternary expression
 358 |  if (_totalAssets >= totalDebt_) {
 359 |      return _shares;
 360 |  } else {
 361 |      // If the vault controls less assets than what has been deposited a share will be worth a
 362 |      // proportional amount of the total assets. This can happen due to fees, slippage, or loss
 363 |      // of funds in the underlying yield vault.
 364 |      return _shares.mulDiv(_totalAssets, totalDebt_, Math.Rounding.Down);
 365 |  }

     |  // @audit-issue Convert to a ternary expression
 461 |  if (_totalAssets >= totalDebt_) {
 462 |      return _assets;
 463 |  } else {
 464 |      // Follows the inverse conversion of `convertToAssets`
 465 |      return _assets.mulDiv(totalDebt_, _totalAssets, Math.Rounding.Up);
 466 |  }

     |  // @audit-issue Convert to a ternary expression
 600 |  if (totalYieldBalance_ >= _yieldBuffer) {
 601 |      return _yieldBuffer;
 602 |  } else {
 603 |      return totalYieldBalance_;
 604 |  }
```

*GitHub* : [344-351](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L344-L351), [358-365](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L358-L365), [461-466](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L461-L466), [600-604](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L600-L604)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Convert to a ternary expression
  85 |  if (_hooks[_winner].useBeforeClaimPrize) {
  86 |      recipient = _hooks[_winner].implementation.beforeClaimPrize{ gas: HOOK_GAS }(
  87 |          _winner,
  88 |          _tier,
  89 |          _prizeIndex,
  90 |          _reward,
  91 |          _rewardRecipient
  92 |      );
  93 |  } else {
  94 |      recipient = _winner;
  95 |  }
```

*GitHub* : [85-95](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L85-L95)

### [N-61]<a name="n-61"></a> Use the latest Solidity version for deployment

When deploying contracts, you should use the latest released version of Solidity (0.8.24). Apart from exceptional cases, only the latest version receives security fixes. Since deployed contracts should not use floating pragmas, I've flagged all instances where a version prior to 0.8.24 is allowed by the version pragma.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Update to target 0.8.24
   2 |  pragma solidity ^0.8.0;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L2)

### [N-62]<a name="n-62"></a> `constant`s should be defined rather than using magic numbers

Magic numbers are prone to error and reduce contract readability. This applies to assembly, too.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Define a named constant instead of using `18`
 305 |  _underlyingDecimals = success ? assetDecimals : 18;
  :  |
     |  // @audit-issue Define a named constant instead of using `32`
 776 |  if (success && encodedDecimals.length >= 32) {
```

*GitHub* : [305](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L305), [776](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L776)

### [N-63]<a name="n-63"></a> `public` functions not called by the contract should be declared `external` instead

Contracts [are allowed](https://docs.soliditylang.org/en/latest/contracts.html#function-overriding) to override their parents' functions and change the visibility from `external` to `public`.

*There are 10 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-info Context
  65 |  contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {
  :  |
     |      // @audit-issue Not called internally by this contract
 320 |      function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {
  :  |
     |      // @audit-issue Not called internally by this contract
 341 |      function convertToShares(uint256 _assets) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 397 |      function maxMint(address _owner) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 404 |      function maxWithdraw(address _owner) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 415 |      function maxRedeem(address _owner) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 584 |      function totalYieldBalance() public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 631 |      function liquidatableBalanceOf(address _tokenOut) public view returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
 659 |      function transferTokensOut(
 660 |          address,
 661 |          address _receiver,
 662 |          address _tokenOut,
 663 |          uint256 _amountOut
 664 |      ) public virtual onlyLiquidationPair returns (bytes memory) {
```

*GitHub* : [320](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L320), [341](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L341), [397](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L397), [404](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L404), [415](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L415), [584](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L584), [631](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L631), [659-664](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L659-L664)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-info Context
  19 |  contract TwabERC20 is ERC20, ERC20Permit {
  :  |
     |      // @audit-issue Not called internally by this contract
  56 |      function balanceOf(
  57 |          address _account
  58 |      ) public view virtual override(ERC20) returns (uint256) {
  :  |
     |      // @audit-issue Not called internally by this contract
  63 |      function totalSupply() public view virtual override(ERC20) returns (uint256) {
```

*GitHub* : [56-58](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L56-L58), [63](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L63)

### Disputed Risk Issues

### [D-01]<a name="d-01"></a> All `verbatim` blocks are considered identical by deduplicator and can incorrectly be unified

> The below source files do not trigger the bug as they do not use `verbatim` in a Yul `assembly` block, or the compiler version is not applicable (`>= 0.8.5`).

The block deduplicator is a step of the opcode-based optimizer which identifies equivalent assembly blocks and merges them into a single one. However, when blocks contained `verbatim`, their comparison was performed incorrectly, leading to the collapse of assembly blocks which are identical except for the contents of the ``verbatim`` items. Since `verbatim` is only available in Yul, compilation of Solidity sources is not affected. For more details check the following [link](https://blog.soliditylang.org/2023/11/08/verbatim-invalid-deduplication-bug/).
                    
This bug affects all versions of Solidity from 0.8.5 onwards, and has not yet been fixed.

*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L2)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L2)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L2)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L2)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

   2 |  pragma solidity ^0.8.0;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L2)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L2)

### [D-02]<a name="d-02"></a> Complex casting

> Address/contract conversions are not generally considered complex

Consider whether the number of casts is really necessary, or whether using a different type would be more appropriate. Alternatively, add comments to explain in detail why the casts are necessary, and any implicit reasons why the cast does not introduce an overflow.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Reconsider complex casting
 540 |  IERC20Permit(address(_asset)).permit(_owner, address(this), _assets, _deadline, _v, _r, _s);
```

*GitHub* : [540](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L540)

### [D-03]<a name="d-03"></a> Consider using SMTChecker

> Exactly the same as *'Consider adding formal verification proofs'*



*There are 6 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L1)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L1)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L1)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L1)

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

     |  // @audit-issue SMT checker was not detected as enabled for this file
   1 |  // SPDX-License-Identifier: MIT
```

*GitHub* : [1](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L1)

### [D-04]<a name="d-04"></a> Consider using named function arguments

> These function calls involve fewer than 4 parameters, and are unlikely to be benefit from named parameters.

Named function calls in Solidity greatly improve code readability by explicitly mapping arguments to their respective parameter names. This clarity becomes critical when dealing with functions that have numerous or complex parameters, reducing potential errors due to misordered arguments. Therefore, adopting named function calls contributes to more maintainable and less error-prone code. The following findings are for function calls with 4 or more praameters.

*There are 39 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider named parameters
 303 |  IERC20 asset_ = IERC20(yieldVault_.asset());

     |  // @audit-issue Consider named parameters
 304 |  (bool success, uint8 assetDecimals) = _tryGetAssetDecimals(asset_);

     |  // @audit-issue Consider named parameters
 311 |  _setYieldFeeRecipient(yieldFeeRecipient_);

     |  // @audit-issue Consider named parameters
 312 |  _setYieldFeePercentage(yieldFeePercentage_);

     |  // @audit-issue Consider named parameters
 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

     |  // @audit-issue Consider named parameters
 343 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Consider named parameters
 357 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Consider named parameters
 377 |  if (totalAssets() < totalDebt_) return 0;

     |  // @audit-issue Consider named parameters
 408 |  uint256 _ownerAssets = convertToAssets(balanceOf(_owner));

     |  // @audit-issue Consider named parameters
 423 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Consider named parameters
 455 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Consider named parameters
 458 |  if (_totalAssets == 0) revert ZeroTotalAssets();

     |  // @audit-issue Consider named parameters
 471 |  return convertToAssets(_shares);

     |  // @audit-issue Consider named parameters
 585 |  return _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Consider named parameters
 592 |  return _availableYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Consider named parameters
 598 |  uint256 totalYieldBalance_ = _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Consider named parameters
 619 |  _mint(msg.sender, _shares);

     |  // @audit-issue Consider named parameters
 648 |  _availableYieldBalance(totalAssets(), _totalDebt(_totalSupply))

     |  // @audit-issue Consider named parameters
 690 |  _withdraw(_receiver, _amountOut);            

     |  // @audit-issue Consider named parameters
 692 |  _mint(_receiver, _amountOut);

     |  // @audit-issue Consider named parameters
 736 |  _setClaimer(_claimer);

     |  // @audit-issue Consider named parameters
 754 |  _setYieldFeePercentage(_yieldFeePercentage);

     |  // @audit-issue Consider named parameters
 760 |  _setYieldFeeRecipient(_yieldFeeRecipient);

     |  // @audit-issue Consider named parameters
 845 |  if (_assets == 0) revert DepositZeroAssets();

     |  // @audit-issue Consider named parameters
 866 |  uint256 _assetsUsed = yieldVault.mint(_yieldVaultShares, address(this));

     |  // @audit-issue Consider named parameters
 872 |  _mint(_receiver, _shares);

     |  // @audit-issue Consider named parameters
 874 |  if (totalAssets() < totalDebt()) revert LossyDeposit(totalAssets(), totalDebt());

     |  // @audit-issue Consider named parameters
 874 |  if (totalAssets() < totalDebt()) revert LossyDeposit(totalAssets(), totalDebt());

     |  // @audit-issue Consider named parameters
 894 |  if (_assets == 0) revert WithdrawZeroAssets();

     |  // @audit-issue Consider named parameters
 906 |  _burn(_owner, _shares);

     |  // @audit-issue Consider named parameters
 907 |  _withdraw(_receiver, _assets);

     |  // @audit-issue Consider named parameters
 922 |  return yieldVault.convertToAssets(yieldVault.maxRedeem(address(this)));

     |  // @audit-issue Consider named parameters
 939 |  _asset.transfer(_receiver, _assets);
```

*GitHub* : [303](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L303), [304](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L304), [311](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L311), [312](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L312), [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [343](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L343), [357](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L357), [377](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L377), [408](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L408), [423](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L423), [455](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L455), [458](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L458), [471](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L471), [585](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L585), [592](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L592), [598](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L598), [619](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L619), [648](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L648), [690](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L690), [692](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L692), [736](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L736), [754](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L754), [760](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L760), [845](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L845), [866](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L866), [872](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L872), [874](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L874), [874](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L874), [894](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L894), [906](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L906), [907](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L907), [922](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L922), [939](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L939)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Consider named parameters
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);

     |  // @audit-issue Consider named parameters
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118), [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Consider named parameters
  77 |  twabController.mint(_receiver, SafeCast.toUint96(_amount));

     |  // @audit-issue Consider named parameters
  88 |  twabController.burn(_owner, SafeCast.toUint96(_amount));

     |  // @audit-issue Consider named parameters
 101 |  twabController.transfer(_from, _to, SafeCast.toUint96(_amount));
```

*GitHub* : [77](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L77), [88](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L88), [101](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L101)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Consider named parameters
  67 |  _setClaimer(claimer_);
```

*GitHub* : [67](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L67)

### [D-05]<a name="d-05"></a> Consider using solady's "FixedPointMathLib"

> These instances are duplicates of *'Consider Using Solady's Gas Optimized Lib for Math'*, or are incorrect e.g. simple division or multiplication.

In instances where many similar mathematical operations are performed, consider using Solday's math lib to benefit from the gas saving it can introduce.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 672 |  if (_yieldFeePercentage != 0) {
 673 |      // The yield fee is calculated as a portion of the total yield being consumed, such that 
 674 |      // `total = amountOut + yieldFee` and `yieldFee / total = yieldFeePercentage`. 
 675 |      _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;
 676 |  }

 675 |  _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;
```

*GitHub* : [672-676](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L672-L676), [675](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L675)

### [D-06]<a name="d-06"></a> Contracts and libraries should use fixed compiler versions

> This finding only applies to contracts and libraries

To prevent the actual contracts being deployed from behaving differently depending on the compiler version, it is recommended to use fixed solidity versions for contracts and libraries.

Although we can configure a specific version through config (like hardhat, forge config files), it is recommended to **set the fixed version in the solidity pragma directly** before deploying to the mainnet.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L2)

### [D-07]<a name="d-07"></a> Contracts are vulnerable to fee-on-transfer accounting-related issues

> The readme **specifically excludes** fee-on-transfer tokens

Some tokens take a transfer fee (e.g. STA, PAXG), some do not currently charge a fee but may do so in the future (e.g. USDT, USDC). The functions below transfer funds from the caller to the receiver via `transferFrom()`, but do not ensure that the actual number of tokens received is the same as the input amount to the transfer. If the token is a fee-on-transfer token, the balance after the transfer will be smaller than expected, leading to accounting issues. Even if there are checks later, related to a secondary transfer, an attacker may be able to use latent funds (e.g. mistakenly sent by another user) in order to get a free credit.

One way to solve this problem is to measure the balance before and after the transfer, and use the difference as the amount, rather than the stated amount.

*There are 2 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Check balance before & after vs. expected
 854 |  _asset.safeTransferFrom(
 855 |      _caller,
 856 |      address(this),
 857 |      _assets
 858 |  );
```

*GitHub* : [854-858](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L854-L858)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Check balance before & after vs. expected
 118 |  IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);
```

*GitHub* : [118](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L118)

### [D-08]<a name="d-08"></a> Floating pragma should be avoided

> These are either duplicates of *'Fixed Compiler Version Required for Non-Library/Interface Files'* or not floating pragmas at all.



*There are 5 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Invalid or already covered elsewhere
   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L2)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

     |  // @audit-issue Invalid or already covered elsewhere
   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L2)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

     |  // @audit-issue Invalid or already covered elsewhere
   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L2)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

     |  // @audit-issue Invalid or already covered elsewhere
   2 |  pragma solidity ^0.8.24;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L2)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Invalid or already covered elsewhere
   2 |  pragma solidity ^0.8.0;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L2)

### [D-09]<a name="d-09"></a> Lack of two-step update for critical functions

> It doesn't make sense to do a two-step update for non-address parameters, as there is no recipient to confirm. Instead, a timelock ought to be used for sensitive non-address parameter changes, to allow time to make corrections.

Critical functions in Solidity contracts should follow a two-step procedure to enhance security, minimize human error, and ensure proper access control. By dividing sensitive operations into distinct phases, such as initiation and confirmation, developers can introduce a safeguard against unintended actions or unauthorized access.

*There are 3 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Consider implementing two-step verification of the new value
 753 |  function setYieldFeePercentage(uint32 _yieldFeePercentage) external onlyOwner {

     |  // @audit-issue Consider implementing two-step verification of the new value
 947 |  function _setYieldFeePercentage(uint32 _yieldFeePercentage) internal {
```

*GitHub* : [753](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L753), [947](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L947)

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Consider implementing two-step verification of the new value
  29 |  function setHooks(VaultHooks calldata hooks) external {
```

*GitHub* : [29](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L29)

### [D-10]<a name="d-10"></a> Natspec comments are missing from scope blocks

> NatSpec does not apply to scope blocks



*There are 41 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 344 |  if (_totalAssets >= totalDebt_) {

 346 |  } else {

 358 |  if (_totalAssets >= totalDebt_) {

 360 |  } else {

 384 |  if (_latentBalance >= _maxYieldVaultDeposit) {

 386 |  } else {

 422 |  if (_ownerShares > _maxWithdraw) {

 425 |  if (_totalAssets >= totalDebt_) {

 427 |  } else {

 435 |  } else {

 461 |  if (_totalAssets >= totalDebt_) {

 463 |  } else {

 532 |  if (_owner != msg.sender) {

 539 |  if (_asset.allowance(_owner, address(this)) != _assets) {

 558 |  if (twabController.delegateOf(address(this), _owner) != SPONSORSHIP_ADDRESS) {

 600 |  if (totalYieldBalance_ >= _yieldBuffer) {

 602 |  } else {

 634 |  if (_tokenOut == address(this)) {

 637 |  } else if (_tokenOut == address(_asset)) {

 640 |  } else {

 672 |  if (_yieldFeePercentage != 0) {

 679 |  if (_amountOut + _yieldFee > _availableYield) {

 684 |  if (_yieldFee > 0) {

 689 |  if (_tokenOut == address(_asset)) {

 691 |  } else if (_tokenOut == address(this)) {

 693 |  } else {

 709 |  if (_tokenIn != _prizeToken) {

 776 |  if (success && encodedDecimals.length >= 32) {

 778 |  if (returnedDecimals <= type(uint8).max) {

 809 |  if (totalDebt_ >= _totalAssets) {

 811 |  } else {

 826 |  if (totalYieldBalance_ >= _yieldBuffer) {

 830 |  } else {

 867 |  if (_assetsUsed != _assetsWithDust) {

 896 |  if (_caller != _owner) {

 932 |  if (_assets > _latentAssets) {

 938 |  if (_receiver != address(this)) {

 948 |  if (_yieldFeePercentage > MAX_YIELD_FEE) {
```

*GitHub* : [344](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L344), [346](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L346), [358](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L358), [360](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L360), [384](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L384), [386](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L386), [422](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L422), [425](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L425), [427](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L427), [435](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L435), [461](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L461), [463](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L463), [532](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L532), [539](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L539), [558](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L558), [600](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L600), [602](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L602), [634](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L634), [637](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L637), [640](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L640), [672](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L672), [679](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L679), [684](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L684), [689](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L689), [691](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L691), [693](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L693), [709](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L709), [776](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L776), [778](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L778), [809](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L809), [811](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L811), [826](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L826), [830](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L830), [867](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L867), [896](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L896), [932](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L932), [938](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L938), [948](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L948)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

  85 |  if (_hooks[_winner].useBeforeClaimPrize) {

  93 |  } else {

 108 |  if (_hooks[_winner].useAfterClaimPrize) {
```

*GitHub* : [85](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L85), [93](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L93), [108](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L108)

### [D-11]<a name="d-11"></a> Natspec is missing from struct

> NatSpec does not apply to structs. While the compiler does not produce an error, there is no `devdoc` node in the output.

NatSpec is not supported for `struct`. Test case:

```solidity
/// @title titlenatspec
/// @dev devnatspec
/// @param paramnatspec test
/// @notice noticenatspec
struct A { // produces no `devdoc` node
    uint256 a;
}


/// @title titlenatspec
/// @dev devnatspec
/// @notice noticenatspec
contract B { // produces a `devdoc` node
    uint256 b;
}
```

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol

   8 |  struct VaultHooks {
```

*GitHub* : [8](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L8)

### [D-12]<a name="d-12"></a> Optimize Gas by Splitting if() revert Statements

> This is completely incorrect; in Solidity,  the operators `||` and `&&` [apply the common short-circuiting rules](https://docs.soliditylang.org/en/latest/types.html#booleans)

Optimizing gas in smart contracts is crucial for performance and cost-effectiveness. One strategy to achieve this is splitting if() statements accompanied by revert() into separate lines, rather than chaining them with the || (OR) boolean operator. This is because, in Solidity, when conditions are chained using ||, all conditions might get evaluated even if one of them is true, resulting in unnecessary gas consumption. By breaking them into separate if() statements, the contract will exit as soon as one condition is met, saving gas.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 776 |  if (success && encodedDecimals.length >= 32) {
```

*GitHub* : [776](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L776)

### [D-13]<a name="d-13"></a> Revert statements within external and public functions can be used to perform DOS attacks

> This is generic, non-sensical, irrelevant encylopedia-style output from an LLM (e.g. ChatGPT) that does not highlight a specific issue.

In Solidity, 'revert' statements are used to undo changes and throw an exception when certain conditions are not met. However, in public and external functions, improper use of `revert` can be exploited for Denial of Service (DoS) attacks. An attacker can intentionally trigger these 'revert' conditions, causing legitimate transactions to consistently fail. For example, if a function relies on specific conditions from user input or contract state, an attacker could manipulate these to continually force reverts, blocking the function's execution. Therefore, it's crucial to design contract logic to handle exceptions properly and avoid scenarios where `revert` can be predictably triggered by malicious actors. This includes careful input validation and considering alternative design patterns that are less susceptible to such abuses.

*There are 13 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 289 |  constructor(
 290 |      string memory name_,
 291 |      string memory symbol_,
 292 |      IERC4626 yieldVault_,
 293 |      PrizePool prizePool_,
 294 |      address claimer_,
 295 |      address yieldFeeRecipient_,
 296 |      uint32 yieldFeePercentage_,
 297 |      uint256 yieldBuffer_,
 298 |      address owner_
 299 |  ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {
 300 |      if (address(yieldVault_) == address(0)) revert YieldVaultZeroAddress();
 301 |      if (owner_ == address(0)) revert OwnerZeroAddress();

 454 |  function previewWithdraw(uint256 _assets) public view returns (uint256) {
  :  |
 458 |      if (_totalAssets == 0) revert ZeroTotalAssets();

 524 |  function depositWithPermit(
 525 |      uint256 _assets,
 526 |      address _owner,
 527 |      uint256 _deadline,
 528 |      uint8 _v,
 529 |      bytes32 _r,
 530 |      bytes32 _s
 531 |  ) external returns (uint256) {
  :  |
 533 |          revert PermitCallerNotOwner(msg.sender, _owner);

 611 |  function claimYieldFeeShares(uint256 _shares) external onlyYieldFeeRecipient {
 612 |      if (_shares == 0) revert MintZeroShares();
  :  |
 615 |      if (_shares > _yieldFeeBalance) revert SharesExceedsYieldFeeBalance(_shares, _yieldFeeBalance);

 659 |  function transferTokensOut(
 660 |      address,
 661 |      address _receiver,
 662 |      address _tokenOut,
 663 |      uint256 _amountOut
 664 |  ) public virtual onlyLiquidationPair returns (bytes memory) {
 665 |      if (_amountOut == 0) revert LiquidationAmountOutZero();
  :  |
 680 |          revert LiquidationExceedsAvailable(_amountOut + _yieldFee, _availableYield);
  :  |
 694 |          revert LiquidationTokenOutNotSupported(_tokenOut);

 703 |  function verifyTokensIn(
 704 |      address _tokenIn,
 705 |      uint256 _amountIn,
 706 |      bytes calldata
 707 |  ) external onlyLiquidationPair {
  :  |
 710 |          revert LiquidationTokenInNotPrizeToken(_tokenIn, _prizeToken);

 742 |  function setLiquidationPair(address _liquidationPair) external onlyOwner {
 743 |      if (address(_liquidationPair) == address(0)) revert LPZeroAddress();
```

*GitHub* : [300](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L300), [301](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L301), [458](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L458), [533](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L533), [612](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L612), [615](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L615), [665](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L665), [680](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L680), [694](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L694), [710](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L710), [743](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L743)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

  42 |  constructor(
  43 |      string memory name_,
  44 |      string memory symbol_,
  45 |      TwabController twabController_
  46 |  ) ERC20(name_, symbol_) ERC20Permit(name_) {
  47 |      if (address(0) == address(twabController_)) revert TwabControllerZeroAddress();
```

*GitHub* : [47](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L47)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

  76 |  function claimPrize(
  77 |      address _winner,
  78 |      uint8 _tier,
  79 |      uint32 _prizeIndex,
  80 |      uint96 _reward,
  81 |      address _rewardRecipient
  82 |  ) external onlyClaimer returns (uint256) {
  :  |
  97 |      if (recipient == address(0)) revert ClaimRecipientZeroAddress();
```

*GitHub* : [97](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L97)

### [D-14]<a name="d-14"></a> Solidity version 0.8.20 may not work on other chains due to `PUSH0`

> The `readme.md` specifically states L2s are **NOT** in scope, thus this finding is not applicable

The compiler for Solidity 0.8.20 switches the default target EVM version to [Shanghai](https://blog.soliditylang.org/2023/05/10/solidity-0.8.20-release-announcement/#important-note), which includes the new `PUSH0` op code. This op code may not yet be implemented on all L2s, so deployment on these chains will fail. To work around this issue, use an earlier [EVM](https://docs.soliditylang.org/en/v0.8.20/using-the-compiler.html?ref=zaryabs.com#setting-the-evm-version-to-target) [version](https://book.getfoundry.sh/reference/config/solidity-compiler#evm_version). While the project itself may or may not compile with 0.8.20, other projects with which it integrates, or which extend this project may, and those projects will have problems deploying these contracts/libraries.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/abstract/HookManager.sol

     |  // @audit-issue Require Solidity 0.8.19 or lower
   2 |  pragma solidity ^0.8.0;
```

*GitHub* : [2](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/HookManager.sol#L2)

### [D-15]<a name="d-15"></a> Structs can be packed into fewer storage slots

> Cygnet's optimization algorithm couldn't improve this layout, carefully review any claims stating otherwise

Each slot saved can avoid an extra Gsset (20000 gas) for the first setting of the struct. Subsequent reads as well as writes have smaller gas savings

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol
Struct VaultHooks

     |  // @audit-issue Can't improve current layout of 1 slots!
     |  // slot[0] = useAfterClaimPrize (bool/1 bytes), useBeforeClaimPrize (bool/1 bytes), implementation (contract/20 bytes)
   8 |  struct VaultHooks {
   9 |      bool useBeforeClaimPrize;
  10 |      bool useAfterClaimPrize;
  11 |      IVaultHooks implementation;
  12 |  }
```

*GitHub* : [8-12](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L8-L12)

### [D-16]<a name="d-16"></a> Structs can be packed into fewer storage slots by truncating timestamp bytes

> Cygnet's optimization algorithm couldn't improve this layout, carefully review any claims stating otherwise

Each slot saved can avoid an extra Gsset (20000 gas) for the first setting of the struct. Subsequent reads as well as writes have smaller gas savings

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/interfaces/IVaultHooks.sol
Struct VaultHooks

     |  // @audit-issue Can't improve current layout of 1 slots!
     |  // slot[0] = useBeforeClaimPrize (bool/1 bytes), useAfterClaimPrize (bool/1 bytes), implementation (contract/20 bytes)
   8 |  struct VaultHooks {
   9 |      bool useBeforeClaimPrize;
  10 |      bool useAfterClaimPrize;
  11 |      IVaultHooks implementation;
  12 |  }
```

*GitHub* : [8-12](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/interfaces/IVaultHooks.sol#L8-L12)

### [D-17]<a name="d-17"></a> Trade-offs Between Modifiers and Internal Functions

> This is generic, non-sensical, irrelevant encylopedia-style output from an LLM (e.g. ChatGPT) that does not highlight a specific issue.

In Solidity, both modifiers and internal functions can be used to modularize and reuse code, but they have different trade-offs.

Modifiers are primarily used to augment the behavior of functions, often for checks or validations. They can access parameters of the function they modify and are integrated into the function’s code at compile time. This makes them syntactically cleaner for repetitive precondition checks. However, modifiers can sometimes lead to less readable code, especially when the logic is complex or when multiple modifiers are used on a single function.

Internal functions, on the other hand, offer more flexibility. They can contain complex logic, return values, and be called from other functions. This makes them more suitable for reusable chunks of business logic. Since internal functions are separate entities, they can be more readable and easier to test in isolation compared to modifiers.

Using internal functions can result in slightly more gas consumption, as it involves an internal function call. However, this cost is usually minimal and can be a worthwhile trade-off for increased code clarity and maintainability.

In summary, while modifiers offer a concise way to include checks and simple logic across multiple functions, internal functions provide more flexibility and are better suited for complex and reusable code. The choice between the two should be based on the specific use case, considering factors like code complexity, readability, and gas efficiency.

*There are 19 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

 772 |  function _tryGetAssetDecimals(IERC20 asset_) internal view returns (bool, uint8) {

 790 |  function _totalDebt(uint256 _totalSupply) internal view returns (uint256) {

 798 |  function _twabSupplyLimit(uint256 _totalSupply) internal pure returns (uint256) {

 808 |  function _totalYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal pure returns (uint256) {

 823 |  function _availableYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal view returns (uint256) {

 843 |  function _depositAndMint(address _caller, address _receiver, uint256 _assets, uint256 _shares) internal {

 887 |  function _burnAndWithdraw(
 888 |      address _caller,
 889 |      address _receiver,
 890 |      address _owner,
 891 |      uint256 _shares,
 892 |      uint256 _assets
 893 |  ) internal {

 921 |  function _maxYieldVaultWithdraw() internal view returns (uint256) {

 928 |  function _withdraw(address _receiver, uint256 _assets) internal {

 947 |  function _setYieldFeePercentage(uint32 _yieldFeePercentage) internal {

 958 |  function _setYieldFeeRecipient(address _yieldFeeRecipient) internal {

 260 |  modifier onlyLiquidationPair() {

 268 |  modifier onlyYieldFeeRecipient() {
```

*GitHub* : [772](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L772), [790](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L790), [798](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L798), [808](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L808), [823](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L823), [843](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L843), [887-893](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L887-L893), [921](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L921), [928](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L928), [947](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L947), [958](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L958), [260](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L260), [268](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L268)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

  76 |  function _mint(address _receiver, uint256 _amount) internal virtual override {

  87 |  function _burn(address _owner, uint256 _amount) internal virtual override {

 100 |  function _transfer(address _from, address _to, uint256 _amount) internal virtual override {
```

*GitHub* : [76](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L76), [87](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L87), [100](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L100)

```solidity
File: pt-v5-vault/src/abstract/Claimable.sol

  64 |  constructor(PrizePool prizePool_, address claimer_) {

 128 |  function _setClaimer(address _claimer) internal {

  52 |  modifier onlyClaimer() {
```

*GitHub* : [64](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L64), [128](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L128), [52](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/abstract/Claimable.sol#L52)

### [D-18]<a name="d-18"></a> Upgradeable contract uses non-upgradeable version of the OpenZeppelin libraries/contracts

> This file doesn't contain any upgradeable contracts

OpenZeppelin has an [Upgradeable](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/tree/master/contracts/utils) variants of each of its libraries and contracts, and upgradeable contracts should use those variants.

*There are 8 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

   4 |  import { IERC4626 } from "openzeppelin/interfaces/IERC4626.sol";

   5 |  import { SafeERC20, IERC20Permit } from "openzeppelin/token/ERC20/utils/SafeERC20.sol";

   6 |  import { ERC20, IERC20, IERC20Metadata } from "openzeppelin/token/ERC20/ERC20.sol";

   7 |  import { Math } from "openzeppelin/utils/math/Math.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L4), [5](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L5), [6](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L6), [7](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L7)

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

   4 |  import { IERC20, IERC4626 } from "openzeppelin/token/ERC20/extensions/ERC4626.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L4)

```solidity
File: pt-v5-vault/src/TwabERC20.sol

   4 |  import { ERC20 } from "openzeppelin/token/ERC20/ERC20.sol";

   5 |  import { ERC20Permit } from "openzeppelin/token/ERC20/extensions/ERC20Permit.sol";

   6 |  import { SafeCast } from "openzeppelin/utils/math/SafeCast.sol";
```

*GitHub* : [4](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L4), [5](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L5), [6](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/TwabERC20.sol#L6)

### [D-19]<a name="d-19"></a> Use Unchecked for Divisions on Constant or Immutable Values

> Duplicate of *'Divisions which do not divide by -X cannot overflow or overflow so such operations can be unchecked to save gas'*



*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Use unchecked to save gas, if possible
 675 |  _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;
```

*GitHub* : [675](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L675)

### [D-20]<a name="d-20"></a> Use assembly to perform external calls, in order to save gas

> These function calls take more than 2 arguments, or are not external calls

Using Solidity's assembly scratch space for constructing calldata in external calls with one or two arguments can be a gas-efficient approach. This method leverages the designated memory area (the first 64 bytes of memory) for temporary data storage during assembly operations. By directly writing arguments into this scratch space, it eliminates the need for additional memory allocation typically required for calldata preparation. This technique can lead to notable gas savings, especially in high-frequency or gas-sensitive operations. However, it requires careful implementation to avoid data corruption and should be used with a thorough understanding of low-level EVM operations and memory handling. Proper testing and validation are crucial when employing such optimizations.

*There are 86 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVault.sol

     |  // @audit-issue Save gas by call this in assembly
 262 |  revert CallerNotLP(msg.sender, liquidationPair);

     |  // @audit-issue Save gas by call this in assembly
 270 |  revert CallerNotYieldFeeRecipient(msg.sender, yieldFeeRecipient);

     |  // @audit-issue Save gas by call this in assembly
 300 |  if (address(yieldVault_) == address(0)) revert YieldVaultZeroAddress();

     |  // @audit-issue Save gas by call this in assembly
 300 |  if (address(yieldVault_) == address(0)) revert YieldVaultZeroAddress();

     |  // @audit-issue Save gas by call this in assembly
 300 |  if (address(yieldVault_) == address(0)) revert YieldVaultZeroAddress();

     |  // @audit-issue Save gas by call this in assembly
 301 |  if (owner_ == address(0)) revert OwnerZeroAddress();

     |  // @audit-issue Save gas by call this in assembly
 301 |  if (owner_ == address(0)) revert OwnerZeroAddress();

     |  // @audit-issue Save gas by call this in assembly
 303 |  IERC20 asset_ = IERC20(yieldVault_.asset());

     |  // @audit-issue Save gas by call this in assembly
 304 |  (bool success, uint8 assetDecimals) = _tryGetAssetDecimals(asset_);

     |  // @audit-issue Save gas by call this in assembly
 311 |  _setYieldFeeRecipient(yieldFeeRecipient_);

     |  // @audit-issue Save gas by call this in assembly
 312 |  _setYieldFeePercentage(yieldFeePercentage_);

     |  // @audit-issue Save gas by call this in assembly
 330 |  return address(_asset);

     |  // @audit-issue Save gas by call this in assembly
 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 337 |  return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 342 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Save gas by call this in assembly
 343 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Save gas by call this in assembly
 350 |  return _assets.mulDiv(totalDebt_, _totalAssets, Math.Rounding.Down);

     |  // @audit-issue Save gas by call this in assembly
 356 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Save gas by call this in assembly
 357 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Save gas by call this in assembly
 364 |  return _shares.mulDiv(_totalAssets, totalDebt_, Math.Rounding.Down);

     |  // @audit-issue Save gas by call this in assembly
 375 |  uint256 _totalSupply = totalSupply();

     |  // @audit-issue Save gas by call this in assembly
 376 |  uint256 totalDebt_ = _totalDebt(_totalSupply);

     |  // @audit-issue Save gas by call this in assembly
 377 |  if (totalAssets() < totalDebt_) return 0;

     |  // @audit-issue Save gas by call this in assembly
 380 |  uint256 twabSupplyLimit_ = _twabSupplyLimit(_totalSupply);

     |  // @audit-issue Save gas by call this in assembly
 382 |  uint256 _latentBalance = _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 383 |  uint256 _maxYieldVaultDeposit = yieldVault.maxDeposit(address(this));

     |  // @audit-issue Save gas by call this in assembly
 398 |  return maxDeposit(_owner);

     |  // @audit-issue Save gas by call this in assembly
 405 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 405 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 408 |  uint256 _ownerAssets = convertToAssets(balanceOf(_owner));

     |  // @audit-issue Save gas by call this in assembly
 408 |  uint256 _ownerAssets = convertToAssets(balanceOf(_owner));

     |  // @audit-issue Save gas by call this in assembly
 416 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 416 |  uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 417 |  uint256 _ownerShares = balanceOf(_owner);

     |  // @audit-issue Save gas by call this in assembly
 423 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Save gas by call this in assembly
 424 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Save gas by call this in assembly
 432 |  uint256 _maxScaledRedeem = _maxWithdraw.mulDiv(totalDebt_, _totalAssets, Math.Rounding.Up);

     |  // @audit-issue Save gas by call this in assembly
 455 |  uint256 _totalAssets = totalAssets();

     |  // @audit-issue Save gas by call this in assembly
 458 |  if (_totalAssets == 0) revert ZeroTotalAssets();

     |  // @audit-issue Save gas by call this in assembly
 460 |  uint256 totalDebt_ = totalDebt();

     |  // @audit-issue Save gas by call this in assembly
 465 |  return _assets.mulDiv(totalDebt_, _totalAssets, Math.Rounding.Up);

     |  // @audit-issue Save gas by call this in assembly
 471 |  return convertToAssets(_shares);

     |  // @audit-issue Save gas by call this in assembly
 476 |  uint256 _shares = previewDeposit(_assets);

     |  // @audit-issue Save gas by call this in assembly
 477 |  _depositAndMint(msg.sender, _receiver, _assets, _shares);

     |  // @audit-issue Save gas by call this in assembly
 483 |  uint256 _assets = previewMint(_shares);

     |  // @audit-issue Save gas by call this in assembly
 484 |  _depositAndMint(msg.sender, _receiver, _assets, _shares);

     |  // @audit-issue Save gas by call this in assembly
 494 |  uint256 _shares = previewWithdraw(_assets);

     |  // @audit-issue Save gas by call this in assembly
 495 |  _burnAndWithdraw(msg.sender, _receiver, _owner, _shares, _assets);

     |  // @audit-issue Save gas by call this in assembly
 505 |  uint256 _assets = previewRedeem(_shares);

     |  // @audit-issue Save gas by call this in assembly
 506 |  _burnAndWithdraw(msg.sender, _receiver, _owner, _shares, _assets);

     |  // @audit-issue Save gas by call this in assembly
 533 |  revert PermitCallerNotOwner(msg.sender, _owner);

     |  // @audit-issue Save gas by call this in assembly
 539 |  if (_asset.allowance(_owner, address(this)) != _assets) {

     |  // @audit-issue Save gas by call this in assembly
 540 |  IERC20Permit(address(_asset)).permit(_owner, address(this), _assets, _deadline, _v, _r, _s);

     |  // @audit-issue Save gas by call this in assembly
 540 |  IERC20Permit(address(_asset)).permit(_owner, address(this), _assets, _deadline, _v, _r, _s);

     |  // @audit-issue Save gas by call this in assembly
 540 |  IERC20Permit(address(_asset)).permit(_owner, address(this), _assets, _deadline, _v, _r, _s);

     |  // @audit-issue Save gas by call this in assembly
 540 |  IERC20Permit(address(_asset)).permit(_owner, address(this), _assets, _deadline, _v, _r, _s);

     |  // @audit-issue Save gas by call this in assembly
 543 |  uint256 _shares = previewDeposit(_assets);

     |  // @audit-issue Save gas by call this in assembly
 544 |  _depositAndMint(_owner, _owner, _assets, _shares);

     |  // @audit-issue Save gas by call this in assembly
 555 |  uint256 _shares = previewDeposit(_assets);

     |  // @audit-issue Save gas by call this in assembly
 556 |  _depositAndMint(_owner, _owner, _assets, _shares);

     |  // @audit-issue Save gas by call this in assembly
 558 |  if (twabController.delegateOf(address(this), _owner) != SPONSORSHIP_ADDRESS) {

     |  // @audit-issue Save gas by call this in assembly
 562 |  emit Sponsor(_owner, _assets, _shares);

     |  // @audit-issue Save gas by call this in assembly
 574 |  return _totalDebt(totalSupply());

     |  // @audit-issue Save gas by call this in assembly
 574 |  return _totalDebt(totalSupply());

     |  // @audit-issue Save gas by call this in assembly
 585 |  return _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Save gas by call this in assembly
 585 |  return _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Save gas by call this in assembly
 585 |  return _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Save gas by call this in assembly
 592 |  return _availableYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Save gas by call this in assembly
 592 |  return _availableYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Save gas by call this in assembly
 592 |  return _availableYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Save gas by call this in assembly
 598 |  uint256 totalYieldBalance_ = _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Save gas by call this in assembly
 598 |  uint256 totalYieldBalance_ = _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Save gas by call this in assembly
 598 |  uint256 totalYieldBalance_ = _totalYieldBalance(totalAssets(), totalDebt());

     |  // @audit-issue Save gas by call this in assembly
 612 |  if (_shares == 0) revert MintZeroShares();

     |  // @audit-issue Save gas by call this in assembly
 615 |  if (_shares > _yieldFeeBalance) revert SharesExceedsYieldFeeBalance(_shares, _yieldFeeBalance);

     |  // @audit-issue Save gas by call this in assembly
 619 |  _mint(msg.sender, _shares);

     |  // @audit-issue Save gas by call this in assembly
 621 |  emit ClaimYieldFeeShares(msg.sender, _shares);

     |  // @audit-issue Save gas by call this in assembly
 632 |  uint256 _totalSupply = totalSupply();

     |  // @audit-issue Save gas by call this in assembly
 634 |  if (_tokenOut == address(this)) {

     |  // @audit-issue Save gas by call this in assembly
 636 |  _maxAmountOut = _twabSupplyLimit(_totalSupply);

     |  // @audit-issue Save gas by call this in assembly
 637 |  } else if (_tokenOut == address(_asset)) {

     |  // @audit-issue Save gas by call this in assembly
 639 |  _maxAmountOut = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 639 |  _maxAmountOut = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

     |  // @audit-issue Save gas by call this in assembly
 648 |  _availableYieldBalance(totalAssets(), _totalDebt(_totalSupply))
 649 |  .mulDiv(FEE_PRECISION - yieldFeePercentage, FEE_PRECISION);

     |  // @audit-issue Save gas by call this in assembly
 648 |  _availableYieldBalance(totalAssets(), _totalDebt(_totalSupply))

     |  // @audit-issue Save gas by call this in assembly
 648 |  _availableYieldBalance(totalAssets(), _totalDebt(_totalSupply))
```

*GitHub* : [262](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L262), [270](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L270), [300](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L300), [300](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L300), [300](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L300), [301](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L301), [301](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L301), [303](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L303), [304](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L304), [311](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L311), [312](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L312), [330](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L330), [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [337](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L337), [342](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L342), [343](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L343), [350](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L350), [356](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L356), [357](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L357), [364](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L364), [375](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L375), [376](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L376), [377](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L377), [380](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L380), [382](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L382), [383](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L383), [398](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L398), [405](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L405), [405](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L405), [408](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L408), [408](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L408), [416](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L416), [416](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L416), [417](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L417), [423](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L423), [424](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L424), [432](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L432), [455](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L455), [458](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L458), [460](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L460), [465](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L465), [471](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L471), [476](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L476), [477](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L477), [483](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L483), [484](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L484), [494](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L494), [495](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L495), [505](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L505), [506](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L506), [533](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L533), [539](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L539), [540](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L540), [540](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L540), [540](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L540), [540](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L540), [543](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L543), [544](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L544), [555](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L555), [556](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L556), [558](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L558), [562](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L562), [574](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L574), [574](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L574), [585](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L585), [585](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L585), [585](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L585), [592](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L592), [592](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L592), [592](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L592), [598](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L598), [598](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L598), [598](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L598), [612](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L612), [615](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L615), [619](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L619), [621](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L621), [632](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L632), [634](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L634), [636](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L636), [637](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L637), [639](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L639), [639](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L639), [648-649](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L648-L649), [648](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L648), [648](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVault.sol#L648)

### [D-21]<a name="d-21"></a> Use bitmap to save gas

> None of these are valid scenarios for a using bitmap

Bitmaps in Solidity are essentially a way of representing a set of boolean values within an integer type variable such as `uint256`. Each bit in the integer represents a true or false value (1 or 0), thus allowing efficient storage of multiple boolean values.

Bitmaps can save gas in the Ethereum network because they condense a lot of information into a small amount of storage. In Ethereum, storage is one of the most significant costs in terms of gas usage. By reducing the amount of storage space needed, you can potentially save on gas fees.

Here's a quick comparison:

If you were to represent 256 different boolean values in the traditional way, you would have to declare 256 different `bool` variables. Given that each `bool` occupies a storage slot and each storage slot costs 20,000 gas to initialize, you would end up paying a considerable amount of gas.

On the other hand, if you were to use a bitmap, you could store these 256 boolean values within a single `uint256` variable. In other words, you'd only pay for a single storage slot, resulting in significant gas savings.

However, it's important to note that while bitmaps can provide gas efficiencies, they do add complexity to the code, making it harder to read and maintain. Also, using bitmaps is efficient only when dealing with a large number of boolean variables that are frequently changed or accessed together. 

In contrast, the straightforward counterpart to bitmaps would be using arrays or mappings to store boolean values, with each `bool` value occupying its own storage slot. This approach is simpler and more readable but could potentially be more expensive in terms of gas usage.

*There are 1 instance(s) of this issue:*

```solidity
File: pt-v5-vault/src/PrizeVaultFactory.sol

 121 |  deployedVaults[address(_vault)] = true;
```

*GitHub* : [121](https://github.com/code-423n4/2024-03-pooltogether/blob/004e027de5569cca5790e6ed80fa51d026df9b75/pt-v5-vault/src/PrizeVaultFactory.sol#L121)