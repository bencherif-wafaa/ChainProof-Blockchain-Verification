// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DataIntegrity
 * @notice Decentralized fake data prevention via cryptographic hashing + digital signatures.
 *         Users store SHA-256 hashes of their files on-chain, signed with their private key.
 *         Anyone can verify both data integrity AND the identity of the signer.
 */
contract DataIntegrity {

    // ─── Structs ─────────────────────────────────────────────────────────────

    struct Record {
        bytes32 hash;        // SHA-256 hash of the original file
        address registrant;  // Address that registered the hash
        uint256 timestamp;   // Block timestamp at registration
        string  label;       // Human-readable description (e.g. filename)
        bytes   signature;   // ECDSA digital signature of the hash
        string  sigMessage;  // The exact message that was signed
        bool    exists;      // Guard against zero-hash false positives
    }

    // ─── State ───────────────────────────────────────────────────────────────

    mapping(bytes32 => Record) private _records;
    mapping(address => bytes32[]) private _byAddress;
    uint256 public totalRecords;

    // ─── Events ──────────────────────────────────────────────────────────────

    event HashRegistered(
        bytes32 indexed hash,
        address indexed registrant,
        uint256 timestamp,
        string  label
    );

    event HashRevoked(
        bytes32 indexed hash,
        address indexed revokedBy,
        uint256 timestamp
    );

    // ─── Errors ──────────────────────────────────────────────────────────────

    error HashAlreadyRegistered(bytes32 hash);
    error HashNotFound(bytes32 hash);
    error NotRegistrant(bytes32 hash, address caller);
    error EmptyHash();
    error InvalidSignature();

    // ─── Write functions ─────────────────────────────────────────────────────

    /**
     * @notice Register a new file hash with a digital signature on-chain.
     * @param hash        The SHA-256 hash of the file, as bytes32.
     * @param label       A short human-readable label.
     * @param signature   The ECDSA signature of sigMessage, signed by the registrant.
     * @param sigMessage  The plain-text message that was signed.
     */
    function registerHash(
        bytes32 hash,
        string  calldata label,
        bytes   calldata signature,
        string  calldata sigMessage
    ) external {
        if (hash == bytes32(0)) revert EmptyHash();
        if (_records[hash].exists) revert HashAlreadyRegistered(hash);
        if (signature.length != 65) revert InvalidSignature();

        _records[hash] = Record({
            hash:       hash,
            registrant: msg.sender,
            timestamp:  block.timestamp,
            label:      label,
            signature:  signature,
            sigMessage: sigMessage,
            exists:     true
        });

        _byAddress[msg.sender].push(hash);
        totalRecords++;

        emit HashRegistered(hash, msg.sender, block.timestamp, label);
    }

    /**
     * @notice Revoke a previously registered hash.
     *         Only the original registrant can revoke.
     */
    function revokeHash(bytes32 hash) external {
        Record storage rec = _records[hash];
        if (!rec.exists) revert HashNotFound(hash);
        if (rec.registrant != msg.sender) revert NotRegistrant(hash, msg.sender);

        emit HashRevoked(hash, msg.sender, block.timestamp);
        delete _records[hash];
        totalRecords--;
    }

    // ─── View functions ──────────────────────────────────────────────────────

    /**
     * @notice Check if a hash is registered.
     */
    function verifyHash(bytes32 hash)
        external view
        returns (bool exists, address registrant, uint256 timestamp, string memory label)
    {
        Record storage rec = _records[hash];
        return (rec.exists, rec.registrant, rec.timestamp, rec.label);
    }

    /**
     * @notice Verify the digital signature of a registered hash on-chain.
     * @return valid           True if the signature is valid and matches the registrant.
     * @return recoveredSigner The address recovered from the signature.
     * @return expectedSigner  The address that registered the hash.
     */
    function verifySignature(bytes32 hash)
        external view
        returns (bool valid, address recoveredSigner, address expectedSigner)
    {
        Record storage rec = _records[hash];
        if (!rec.exists) revert HashNotFound(hash);

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n",
                _uintToStr(bytes(rec.sigMessage).length),
                rec.sigMessage
            )
        );

        recoveredSigner = _recoverSigner(msgHash, rec.signature);
        expectedSigner  = rec.registrant;
        valid           = (recoveredSigner == expectedSigner);
    }

    /**
     * @notice Get all hashes registered by a specific address.
     */
    function getHashesByAddress(address registrant)
        external view returns (bytes32[] memory)
    {
        return _byAddress[registrant];
    }

    /**
     * @notice Get the full record for a hash including signature data.
     */
    function getRecord(bytes32 hash)
        external view
        returns (Record memory)
    {
        if (!_records[hash].exists) revert HashNotFound(hash);
        return _records[hash];
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    function _recoverSigner(bytes32 msgHash, bytes memory sig)
        internal pure returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(sig);
        return ecrecover(msgHash, v, r, s);
    }

    function _splitSignature(bytes memory sig)
        internal pure returns (bytes32 r, bytes32 s, uint8 v)
    {
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function _uintToStr(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}
