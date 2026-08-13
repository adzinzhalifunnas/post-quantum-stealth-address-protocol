// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.28;

/// @title ERC6538Registry — P1's registry, the baseline
/// @notice Faithful port of the ERC-6538 reference registry.
/// @dev Source: `assets/erc-6538/contracts/ERC6538Registry.sol` in ethereum/ERCs,
///      CC0-1.0, retrieved 2026-08-07. Ported unchanged apart from the pragma,
///      raised from 0.8.23 to this project's pinned 0.8.28 so every contract in
///      the study shares one compiler and one optimizer setting.
///
///      The whole contract is ported, not just `registerKeys`, because P1 is the
///      standard we are measuring against and a trimmed-down version would not
///      be it. Note the consequence for reporting: **deployment cost is not
///      comparable across registries.** P1 here is a complete standard
///      implementation with EIP-712 and EIP-1271 signature support, while the P2
///      and P3 registries are minimal. Registration cost per user — the quantity
///      Q2 asks about — is comparable, because `registerKeys` is byte-identical
///      across all of them and only the payload differs.
contract ERC6538Registry {
    /// @notice Emitted when an invalid signature is provided to `registerKeysOnBehalf`.
    error ERC6538Registry__InvalidSignature();

    /// @notice Maps a registrant and scheme id to their stealth meta-address.
    mapping(address registrant => mapping(uint256 schemeId => bytes)) public stealthMetaAddressOf;

    /// @notice A nonce used to ensure a signature can only be used once.
    mapping(address registrant => uint256) public nonceOf;

    /// @notice The EIP-712 type hash used in `registerKeysOnBehalf`.
    bytes32 public constant ERC6538REGISTRY_ENTRY_TYPE_HASH =
        keccak256("Erc6538RegistryEntry(uint256 schemeId,bytes stealthMetaAddress,uint256 nonce)");

    /// @notice The chain ID where this contract is initially deployed.
    uint256 internal immutable INITIAL_CHAIN_ID;

    /// @notice The domain separator used in this contract.
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    /// @notice Emitted when a registrant updates their stealth meta-address.
    /// @param registrant The account that registered the stealth meta-address.
    /// @param schemeId Identifier corresponding to the applied stealth address scheme.
    /// @param stealthMetaAddress The compressed spending and viewing public keys, concatenated.
    event StealthMetaAddressSet(
        address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
    );

    /// @notice Emitted when a registrant increments their nonce.
    /// @param registrant The account that incremented the nonce.
    /// @param newNonce The new nonce value.
    event NonceIncremented(address indexed registrant, uint256 newNonce);

    constructor() {
        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _computeDomainSeparator();
    }

    /// @notice Sets the caller's stealth meta-address for the given scheme ID.
    /// @param schemeId Identifier corresponding to the applied stealth address scheme.
    /// @param stealthMetaAddress The stealth meta-address to register.
    /// @dev This is the function the benchmark measures. It is identical in every
    ///      registry in this study, so measured differences are payload only.
    function registerKeys(uint256 schemeId, bytes calldata stealthMetaAddress) external {
        stealthMetaAddressOf[msg.sender][schemeId] = stealthMetaAddress;
        emit StealthMetaAddressSet(msg.sender, schemeId, stealthMetaAddress);
    }

    /// @notice Sets the `registrant`'s stealth meta-address for the given scheme ID.
    /// @param registrant Address of the registrant.
    /// @param schemeId Identifier corresponding to the applied stealth address scheme.
    /// @param signature A signature from the `registrant` authorizing the registration.
    /// @param stealthMetaAddress The stealth meta-address to register.
    /// @dev Supports both EOA signatures and EIP-1271 signatures. Reverts if invalid.
    function registerKeysOnBehalf(
        address registrant,
        uint256 schemeId,
        bytes memory signature,
        bytes calldata stealthMetaAddress
    ) external {
        bytes32 dataHash;
        address recoveredAddress;

        unchecked {
            dataHash = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR(),
                    keccak256(
                        abi.encode(
                            ERC6538REGISTRY_ENTRY_TYPE_HASH,
                            schemeId,
                            keccak256(stealthMetaAddress),
                            nonceOf[registrant]++
                        )
                    )
                )
            );
        }

        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly ("memory-safe") {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            recoveredAddress = ecrecover(dataHash, v, r, s);
        }

        if (
            (
                (recoveredAddress == address(0) || recoveredAddress != registrant)
                    && (
                        IERC1271(registrant).isValidSignature(dataHash, signature)
                            != IERC1271.isValidSignature.selector
                    )
            )
        ) revert ERC6538Registry__InvalidSignature();

        stealthMetaAddressOf[registrant][schemeId] = stealthMetaAddress;
        emit StealthMetaAddressSet(registrant, schemeId, stealthMetaAddress);
    }

    /// @notice Increments the nonce of the sender to invalidate existing signatures.
    function incrementNonce() external {
        unchecked {
            nonceOf[msg.sender]++;
        }
        emit NonceIncremented(msg.sender, nonceOf[msg.sender]);
    }

    /// @notice Returns the domain separator used in this contract.
    /// @dev The domain separator is re-computed if there's a chain fork.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return
            block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : _computeDomainSeparator();
    }

    /// @notice Computes the domain separator for this contract.
    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("ERC6538Registry"),
                keccak256("1.0"),
                block.chainid,
                address(this)
            )
        );
    }
}

/// @notice Interface of the ERC-1271 standard signature validation method for contracts.
interface IERC1271 {
    /// @notice Should return whether the signature provided is valid for the provided data.
    /// @param hash Hash of the data to be signed.
    /// @param signature Signature byte array associated with the data.
    function isValidSignature(bytes32 hash, bytes memory signature)
        external
        view
        returns (bytes4 magicValue);
}
