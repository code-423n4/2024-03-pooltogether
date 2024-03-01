# Report


## Gas Optimizations


| |Issue|Instances|
|-|:-|:-:|
| [GAS-1](#GAS-1) | `a = a + b` is more gas effective than `a += b` for state variables (excluding arrays and mappings) | 1 |
| [GAS-2](#GAS-2) | Using bools for storage incurs overhead | 1 |
| [GAS-3](#GAS-3) | For Operations that will not overflow, you could use unchecked | 17 |
| [GAS-4](#GAS-4) | Avoid contract existence checks by using low level calls | 8 |
| [GAS-5](#GAS-5) | Functions guaranteed to revert when called by normal users can be marked `payable` | 5 |
| [GAS-6](#GAS-6) | Using `private` rather than `public` for constants, saves gas | 4 |
| [GAS-7](#GAS-7) | Use != 0 instead of > 0 for unsigned integer comparison | 1 |
### <a name="GAS-1"></a>[GAS-1] `a = a + b` is more gas effective than `a += b` for state variables (excluding arrays and mappings)
This saves **16 gas per instance.**

*Instances (1)*:
```solidity
File: src/PrizeVault.sol

685:             yieldFeeBalance += _yieldFee;

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="GAS-2"></a>[GAS-2] Using bools for storage incurs overhead
Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from ‘false’ to ‘true’, after having been ‘true’ in the past. See [source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).

*Instances (1)*:
```solidity
File: src/PrizeVaultFactory.sol

69:     mapping(address vault => bool deployedByFactory) public deployedVaults;

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVaultFactory.sol)

### <a name="GAS-3"></a>[GAS-3] For Operations that will not overflow, you could use unchecked

*Instances (17)*:
```solidity
File: src/PrizeVault.sol

337:         return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

388:                 _maxDeposit = _maxYieldVaultDeposit - _latentBalance;

405:         uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

416:         uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

617:         yieldFeeBalance -= _yieldFeeBalance;

639:             _maxAmountOut = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

649:             .mulDiv(FEE_PRECISION - yieldFeePercentage, FEE_PRECISION);

675:             _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;

679:         if (_amountOut + _yieldFee > _availableYield) {

680:             revert LiquidationExceedsAvailable(_amountOut + _yieldFee, _availableYield);

685:             yieldFeeBalance += _yieldFee;

791:         return _totalSupply + yieldFeeBalance;

800:             return type(uint96).max - _totalSupply;

813:                 return _totalAssets - totalDebt_;

828:                 return totalYieldBalance_ - _yieldBuffer;

934:             uint256 _yieldVaultShares = yieldVault.previewWithdraw(_assets - _latentAssets);

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

```solidity
File: src/PrizeVaultFactory.sol

103:             salt: keccak256(abi.encode(msg.sender, deployerNonces[msg.sender]++))

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVaultFactory.sol)

### <a name="GAS-4"></a>[GAS-4] Avoid contract existence checks by using low level calls
Prior to 0.8.10 the compiler inserted extra code, including `EXTCODESIZE` (**100 gas**), to check for contract existence for external function calls. In more recent solidity versions, the compiler will not insert these checks if the external call has a return value. Similar behavior can be achieved in earlier versions by using low-level calls, since low level calls never check for contract existence

*Instances (8)*:
```solidity
File: src/PrizeVault.sol

337:         return yieldVault.convertToAssets(yieldVault.balanceOf(address(this))) + _asset.balanceOf(address(this));

382:         uint256 _latentBalance = _asset.balanceOf(address(this));

405:         uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

416:         uint256 _maxWithdraw = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

639:             _maxAmountOut = _maxYieldVaultWithdraw() + _asset.balanceOf(address(this));

861:         uint256 _assetsWithDust = _asset.balanceOf(address(this));

931:         uint256 _latentAssets = _asset.balanceOf(address(this));

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

```solidity
File: src/TwabERC20.sol

59:         return twabController.balanceOf(address(this), _account);

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/TwabERC20.sol)

### <a name="GAS-5"></a>[GAS-5] Functions guaranteed to revert when called by normal users can be marked `payable`
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

*Instances (5)*:
```solidity
File: src/PrizeVault.sol

611:     function claimYieldFeeShares(uint256 _shares) external onlyYieldFeeRecipient {

735:     function setClaimer(address _claimer) external onlyOwner {

742:     function setLiquidationPair(address _liquidationPair) external onlyOwner {

753:     function setYieldFeePercentage(uint32 _yieldFeePercentage) external onlyOwner {

759:     function setYieldFeeRecipient(address _yieldFeeRecipient) external onlyOwner {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="GAS-6"></a>[GAS-6] Using `private` rather than `public` for constants, saves gas
If needed, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table

*Instances (4)*:
```solidity
File: src/PrizeVault.sol

74:     uint32 public constant FEE_PRECISION = 1e9;

80:     uint32 public constant MAX_YIELD_FEE = 9e8;

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

```solidity
File: src/PrizeVaultFactory.sol

63:     uint256 public constant YIELD_BUFFER = 1e5;

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVaultFactory.sol)

```solidity
File: src/abstract/Claimable.sol

21:     uint24 public constant HOOK_GAS = 150_000;

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/abstract/Claimable.sol)

### <a name="GAS-7"></a>[GAS-7] Use != 0 instead of > 0 for unsigned integer comparison

*Instances (1)*:
```solidity
File: src/PrizeVault.sol

684:         if (_yieldFee > 0) {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)


## Non Critical Issues


| |Issue|Instances|
|-|:-|:-:|
| [NC-1](#NC-1) | Replace `abi.encodeWithSignature` and `abi.encodeWithSelector` with `abi.encodeCall` which keeps the code typo/type safe | 1 |
| [NC-2](#NC-2) | `constant`s should be defined rather than using magic numbers | 2 |
| [NC-3](#NC-3) | Control structures do not follow the Solidity Style Guide | 19 |
| [NC-4](#NC-4) | Consider disabling `renounceOwnership()` | 1 |
| [NC-5](#NC-5) | Functions should not be longer than 50 lines | 44 |
| [NC-6](#NC-6) | Use a `modifier` instead of a `require/if` statement for a special `msg.sender` actor | 4 |
| [NC-7](#NC-7) | Consider using named mappings | 1 |
| [NC-8](#NC-8) | Take advantage of Custom Error's return value property | 15 |
### <a name="NC-1"></a>[NC-1] Replace `abi.encodeWithSignature` and `abi.encodeWithSelector` with `abi.encodeCall` which keeps the code typo/type safe
When using `abi.encodeWithSignature`, it is possible to include a typo for the correct function signature.
When using `abi.encodeWithSignature` or `abi.encodeWithSelector`, it is also possible to provide parameters that are not of the correct type for the function.

To avoid these pitfalls, it would be best to use [`abi.encodeCall`](https://solidity-by-example.org/abi-encode/) instead.

*Instances (1)*:
```solidity
File: src/PrizeVault.sol

774:             abi.encodeWithSelector(IERC20Metadata.decimals.selector)

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="NC-2"></a>[NC-2] `constant`s should be defined rather than using magic numbers
Even [assembly](https://github.com/code-423n4/2022-05-opensea-seaport/blob/9d7ce4d08bf3c3010304a0476a785c70c0e90ae7/contracts/lib/TokenTransferrer.sol#L35-L39) can benefit from using readable constants instead of hex/numeric literals

*Instances (2)*:
```solidity
File: src/PrizeVault.sol

305:         _underlyingDecimals = success ? assetDecimals : 18;

776:         if (success && encodedDecimals.length >= 32) {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="NC-3"></a>[NC-3] Control structures do not follow the Solidity Style Guide
See the [control structures](https://docs.soliditylang.org/en/latest/style-guide.html#control-structures) section of the Solidity Style Guide

*Instances (19)*:
```solidity
File: src/PrizeVault.sol

300:         if (address(yieldVault_) == address(0)) revert YieldVaultZeroAddress();

301:         if (owner_ == address(0)) revert OwnerZeroAddress();

377:         if (totalAssets() < totalDebt_) return 0;

458:         if (_totalAssets == 0) revert ZeroTotalAssets();

612:         if (_shares == 0) revert MintZeroShares();

615:         if (_shares > _yieldFeeBalance) revert SharesExceedsYieldFeeBalance(_shares, _yieldFeeBalance);

665:         if (_amountOut == 0) revert LiquidationAmountOutZero();

703:     function verifyTokensIn(

743:         if (address(_liquidationPair) == address(0)) revert LPZeroAddress();

844:         if (_shares == 0) revert MintZeroShares();

845:         if (_assets == 0) revert DepositZeroAssets();

874:         if (totalAssets() < totalDebt()) revert LossyDeposit(totalAssets(), totalDebt());

894:         if (_assets == 0) revert WithdrawZeroAssets();

895:         if (_shares == 0) revert BurnZeroShares();

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

```solidity
File: src/TwabERC20.sol

47:         if (address(0) == address(twabController_)) revert TwabControllerZeroAddress();

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/TwabERC20.sol)

```solidity
File: src/abstract/Claimable.sol

53:         if (msg.sender != claimer) revert CallerNotClaimer(msg.sender, claimer);

65:         if (address(prizePool_) == address(0)) revert PrizePoolZeroAddress();

97:         if (recipient == address(0)) revert ClaimRecipientZeroAddress();

129:         if (_claimer == address(0)) revert ClaimerZeroAddress();

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/abstract/Claimable.sol)

### <a name="NC-4"></a>[NC-4] Consider disabling `renounceOwnership()`
If the plan for your project does not include eventually giving up all ownership control, consider overwriting OpenZeppelin's `Ownable`'s `renounceOwnership()` function in order to disable it.

*Instances (1)*:
```solidity
File: src/PrizeVault.sol

65: contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="NC-5"></a>[NC-5] Functions should not be longer than 50 lines
Overly complex code can make understanding functionality more difficult, try to further modularize your code to ensure readability 

*Instances (44)*:
```solidity
File: src/PrizeVault.sol

320:     function decimals() public view override(ERC20, IERC20Metadata) returns (uint8) {

329:     function asset() external view returns (address) {

336:     function totalAssets() public view returns (uint256) {

341:     function convertToShares(uint256 _assets) public view returns (uint256) {

355:     function convertToAssets(uint256 _shares) public view returns (uint256) {

374:     function maxDeposit(address) public view returns (uint256) {

397:     function maxMint(address _owner) public view returns (uint256) {

404:     function maxWithdraw(address _owner) public view returns (uint256) {

415:     function maxRedeem(address _owner) public view returns (uint256) {

441:     function previewDeposit(uint256 _assets) public pure returns (uint256) {

447:     function previewMint(uint256 _shares) public pure returns (uint256) {

454:     function previewWithdraw(uint256 _assets) public view returns (uint256) {

470:     function previewRedeem(uint256 _shares) public view returns (uint256) {

475:     function deposit(uint256 _assets, address _receiver) external returns (uint256) {

482:     function mint(uint256 _shares, address _receiver) external returns (uint256) {

552:     function sponsor(uint256 _assets) external returns (uint256) {

573:     function totalDebt() public view returns (uint256) {

584:     function totalYieldBalance() public view returns (uint256) {

591:     function availableYieldBalance() public view returns (uint256) {

597:     function currentYieldBuffer() external view returns (uint256) {

611:     function claimYieldFeeShares(uint256 _shares) external onlyYieldFeeRecipient {

631:     function liquidatableBalanceOf(address _tokenOut) public view returns (uint256) {

717:     function targetOf(address) external view returns (address) {

735:     function setClaimer(address _claimer) external onlyOwner {

742:     function setLiquidationPair(address _liquidationPair) external onlyOwner {

753:     function setYieldFeePercentage(uint32 _yieldFeePercentage) external onlyOwner {

759:     function setYieldFeeRecipient(address _yieldFeeRecipient) external onlyOwner {

772:     function _tryGetAssetDecimals(IERC20 asset_) internal view returns (bool, uint8) {

790:     function _totalDebt(uint256 _totalSupply) internal view returns (uint256) {

798:     function _twabSupplyLimit(uint256 _totalSupply) internal pure returns (uint256) {

808:     function _totalYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal pure returns (uint256) {

823:     function _availableYieldBalance(uint256 _totalAssets, uint256 totalDebt_) internal view returns (uint256) {

843:     function _depositAndMint(address _caller, address _receiver, uint256 _assets, uint256 _shares) internal {

921:     function _maxYieldVaultWithdraw() internal view returns (uint256) {

928:     function _withdraw(address _receiver, uint256 _assets) internal {

947:     function _setYieldFeePercentage(uint32 _yieldFeePercentage) internal {

958:     function _setYieldFeeRecipient(address _yieldFeeRecipient) internal {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

```solidity
File: src/PrizeVaultFactory.sol

136:     function totalVaults() external view returns (uint256) {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVaultFactory.sol)

```solidity
File: src/TwabERC20.sol

63:     function totalSupply() public view virtual override(ERC20) returns (uint256) {

76:     function _mint(address _receiver, uint256 _amount) internal virtual override {

87:     function _burn(address _owner, uint256 _amount) internal virtual override {

100:     function _transfer(address _from, address _to, uint256 _amount) internal virtual override {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/TwabERC20.sol)

```solidity
File: src/abstract/HookManager.sol

22:     function getHooks(address account) external view returns (VaultHooks memory) {

29:     function setHooks(VaultHooks calldata hooks) external {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/abstract/HookManager.sol)

### <a name="NC-6"></a>[NC-6] Use a `modifier` instead of a `require/if` statement for a special `msg.sender` actor
If a function is supposed to be access-controlled, a `modifier` should be used instead of a `require/if` statement for more readability.

*Instances (4)*:
```solidity
File: src/PrizeVault.sol

261:         if (msg.sender != liquidationPair) {

269:         if (msg.sender != yieldFeeRecipient) {

532:         if (_owner != msg.sender) {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

```solidity
File: src/abstract/Claimable.sol

53:         if (msg.sender != claimer) revert CallerNotClaimer(msg.sender, claimer);

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/abstract/Claimable.sol)

### <a name="NC-7"></a>[NC-7] Consider using named mappings
Consider moving to solidity version 0.8.18 or later, and using [named mappings](https://ethereum.stackexchange.com/questions/51629/how-to-name-the-arguments-in-mapping/145555#145555) to make it easier to understand the purpose of each mapping

*Instances (1)*:
```solidity
File: src/abstract/HookManager.sol

17:     mapping(address => VaultHooks) internal _hooks;

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/abstract/HookManager.sol)

### <a name="NC-8"></a>[NC-8] Take advantage of Custom Error's return value property
An important feature of Custom Error is that values such as address, tokenID, msg.value can be written inside the () sign, this kind of approach provides a serious advantage in debugging and examining the revert details of dapps such as tenderly.

*Instances (15)*:
```solidity
File: src/PrizeVault.sol

300:         if (address(yieldVault_) == address(0)) revert YieldVaultZeroAddress();

301:         if (owner_ == address(0)) revert OwnerZeroAddress();

458:         if (_totalAssets == 0) revert ZeroTotalAssets();

612:         if (_shares == 0) revert MintZeroShares();

665:         if (_amountOut == 0) revert LiquidationAmountOutZero();

743:         if (address(_liquidationPair) == address(0)) revert LPZeroAddress();

844:         if (_shares == 0) revert MintZeroShares();

845:         if (_assets == 0) revert DepositZeroAssets();

874:         if (totalAssets() < totalDebt()) revert LossyDeposit(totalAssets(), totalDebt());

894:         if (_assets == 0) revert WithdrawZeroAssets();

895:         if (_shares == 0) revert BurnZeroShares();

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

```solidity
File: src/TwabERC20.sol

47:         if (address(0) == address(twabController_)) revert TwabControllerZeroAddress();

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/TwabERC20.sol)

```solidity
File: src/abstract/Claimable.sol

65:         if (address(prizePool_) == address(0)) revert PrizePoolZeroAddress();

97:         if (recipient == address(0)) revert ClaimRecipientZeroAddress();

129:         if (_claimer == address(0)) revert ClaimerZeroAddress();

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/abstract/Claimable.sol)


## Low Issues


| |Issue|Instances|
|-|:-|:-:|
| [L-1](#L-1) | `approve()`/`safeApprove()` may revert if the current approval is not zero | 2 |
| [L-2](#L-2) | Use a 2-step ownership transfer pattern | 1 |
| [L-3](#L-3) | Division by zero not prevented | 1 |
| [L-4](#L-4) | Loss of precision | 1 |
| [L-5](#L-5) | Sweeping may break accounting if tokens with multiple addresses are used | 1 |
| [L-6](#L-6) | Unsafe ERC20 operation(s) | 5 |
### <a name="L-1"></a>[L-1] `approve()`/`safeApprove()` may revert if the current approval is not zero
- Some tokens (like the *very popular* USDT) do not work when changing the allowance from an existing non-zero allowance value (it will revert if the current approval is not zero to protect against front-running changes of approvals). These tokens must first be approved for zero and then the actual allowance can be approved.
- Furthermore, OZ's implementation of safeApprove would throw an error if an approve is attempted from a non-zero value (`"SafeERC20: approve from non-zero to non-zero allowance"`)

Set the allowance to zero immediately before each of the existing allowance calls

*Instances (2)*:
```solidity
File: src/PrizeVault.sol

862:         _asset.approve(address(yieldVault), _assetsWithDust);

869:             _asset.approve(address(yieldVault), 0);

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="L-2"></a>[L-2] Use a 2-step ownership transfer pattern
Recommend considering implementing a two step process where the owner or admin nominates an account and the nominated account needs to call an `acceptOwnership()` function for the transfer of ownership to fully succeed. This ensures the nominated EOA account is a valid and active account. Lack of two-step procedure for critical operations leaves them error-prone. Consider adding two step procedure on the critical functions.

*Instances (1)*:
```solidity
File: src/PrizeVault.sol

65: contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="L-3"></a>[L-3] Division by zero not prevented
The divisions below take an input parameter which does not have any zero-value checks, which may lead to the functions reverting when zero is passed.

*Instances (1)*:
```solidity
File: src/PrizeVault.sol

675:             _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="L-4"></a>[L-4] Loss of precision
Division by large numbers may result in the result being zero, due to solidity not supporting fractions. Consider requiring a minimum amount for the numerator to ensure that it is always larger than the denominator

*Instances (1)*:
```solidity
File: src/PrizeVault.sol

675:             _yieldFee = (_amountOut * FEE_PRECISION) / (FEE_PRECISION - _yieldFeePercentage) - _amountOut;

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="L-5"></a>[L-5] Sweeping may break accounting if tokens with multiple addresses are used
There have been [cases](https://blog.openzeppelin.com/compound-tusd-integration-issue-retrospective/) in the past where a token mistakenly had two addresses that could control its balance, and transfers using one address impacted the balance of the other. To protect against this potential scenario, sweep functions should ensure that the balance of the non-sweepable token does not change after the transfer of the swept tokens.

*Instances (1)*:
```solidity
File: src/PrizeVault.sol

206:     error SweepZeroAssets();

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

### <a name="L-6"></a>[L-6] Unsafe ERC20 operation(s)

*Instances (5)*:
```solidity
File: src/PrizeVault.sol

862:         _asset.approve(address(yieldVault), _assetsWithDust);

869:             _asset.approve(address(yieldVault), 0);

939:             _asset.transfer(_receiver, _assets);

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)

```solidity
File: src/PrizeVaultFactory.sol

118:         IERC20(_vault.asset()).transferFrom(msg.sender, address(_vault), YIELD_BUFFER);

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVaultFactory.sol)

```solidity
File: src/TwabERC20.sol

101:         twabController.transfer(_from, _to, SafeCast.toUint96(_amount));

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/TwabERC20.sol)


## Medium Issues


| |Issue|Instances|
|-|:-|:-:|
| [M-1](#M-1) | Centralization Risk for trusted owners | 6 |
### <a name="M-1"></a>[M-1] Centralization Risk for trusted owners

#### Impact:
Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

*Instances (6)*:
```solidity
File: src/PrizeVault.sol

65: contract PrizeVault is TwabERC20, Claimable, IERC4626, ILiquidationSource, Ownable {

299:     ) TwabERC20(name_, symbol_, prizePool_.twabController()) Claimable(prizePool_, claimer_) Ownable(owner_) {

735:     function setClaimer(address _claimer) external onlyOwner {

742:     function setLiquidationPair(address _liquidationPair) external onlyOwner {

753:     function setYieldFeePercentage(uint32 _yieldFeePercentage) external onlyOwner {

759:     function setYieldFeeRecipient(address _yieldFeeRecipient) external onlyOwner {

```
[Link to code](https://github.com/code-423n4/2024-03-pooltogether/blob/main/pt-v5-vault/src/PrizeVault.sol)
