/**
 * blockchain.js
 * Ethers.js v6 integration for the DataIntegrity smart contract.
 * Includes SHA-256 hashing + ECDSA digital signatures + AES-256-GCM encryption + JWT certificates.
 */

// ─── ABI ─────────────────────────────────────────────────────────────────────
export const CONTRACT_ABI = [
  "function registerHash(bytes32 hash, string calldata label, bytes calldata signature, string calldata sigMessage) external",
  "function revokeHash(bytes32 hash) external",
  "function verifyHash(bytes32 hash) external view returns (bool exists, address registrant, uint256 timestamp, string memory label)",
  "function verifySignature(bytes32 hash) external view returns (bool valid, address recoveredSigner, address expectedSigner)",
  "function getHashesByAddress(address registrant) external view returns (bytes32[])",
  "function getRecord(bytes32 hash) external view returns (tuple(bytes32 hash, address registrant, uint256 timestamp, string label, bytes signature, string sigMessage, bool exists))",
  "function totalRecords() external view returns (uint256)",
  "event HashRegistered(bytes32 indexed hash, address indexed registrant, uint256 timestamp, string label)",
  "event HashRevoked(bytes32 indexed hash, address indexed revokedBy, uint256 timestamp)"
];

// ─── Config ───────────────────────────────────────────────────────────────────
export const CONTRACT_ADDRESS = "0x411A74ce58e6d9808C575aE68047f9E882E58a22";
export const SEPOLIA_CHAIN_ID = 11155111;

// ─── JWT Secret ───────────────────────────────────────────────────────────────
// This is the HMAC-SHA256 secret key used to sign JWT tokens.
// In a real production app this would be on a server — here it lives in the browser
// for demonstration purposes, which is standard for client-side JWT demos.
const JWT_SECRET = "DataIntegrity-JWT-Secret-2024-Blockchain-Crypto-Project";

// ─── Wallet connection ────────────────────────────────────────────────────────

export async function connectWallet() {
  if (!window.ethereum) throw new Error("MetaMask not detected. Please install MetaMask.");

  const { ethers } = await import("https://cdn.jsdelivr.net/npm/ethers@6/dist/ethers.min.js");
  const provider = new ethers.BrowserProvider(window.ethereum);
  await provider.send("eth_requestAccounts", []);

  const network = await provider.getNetwork();
  if (Number(network.chainId) !== SEPOLIA_CHAIN_ID) {
    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: "0x" + SEPOLIA_CHAIN_ID.toString(16) }],
      });
    } catch (err) {
      if (err.code === 4902) {
        await window.ethereum.request({
          method: "wallet_addEthereumChain",
          params: [{
            chainId: "0x" + SEPOLIA_CHAIN_ID.toString(16),
            chainName: "Sepolia Test Network",
            nativeCurrency: { name: "SepoliaETH", symbol: "ETH", decimals: 18 },
            rpcUrls: ["https://rpc.sepolia.org"],
            blockExplorerUrls: ["https://sepolia.etherscan.io"],
          }],
        });
      } else { throw err; }
    }
  }

  const signer = await provider.getSigner();
  const address = await signer.getAddress();
  return { provider, signer, address, ethers };
}

// ─── Provider helpers ─────────────────────────────────────────────────────────

export async function getReadOnlyContract() {
  const { ethers } = await import("https://cdn.jsdelivr.net/npm/ethers@6/dist/ethers.min.js");
  const provider = new ethers.JsonRpcProvider("https://eth-sepolia.g.alchemy.com/v2/UbOsw--J9RrnaEzISr3I6");
  return new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, provider);
}

export async function getWritableContract(signer, ethers) {
  return new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);
}

// ─── Hashing ─────────────────────────────────────────────────────────────────

export async function hashFile(file) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return "0x" + hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function hashBuffer(buffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return "0x" + hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// ─── JWT (JSON Web Token) ─────────────────────────────────────────────────────

/**
 * JWT is a standard (RFC 7519) for creating signed tokens that carry claims.
 * Structure: base64(header) . base64(payload) . base64(signature)
 *
 * In this project, a JWT token acts as a PORTABLE CERTIFICATE that proves:
 * - Which file was registered (hash)
 * - Who registered it (wallet address)
 * - When it was registered (timestamp)
 * - That it was stored on the blockchain (txHash, blockNumber)
 *
 * Anyone can verify the JWT without connecting to the blockchain.
 * This is the main difference from blockchain verification:
 *   - Blockchain: needs internet + RPC connection to verify
 *   - JWT: can be verified offline, instantly, by anyone with the secret
 */

/**
 * Base64url encode (JWT uses base64url, not standard base64).
 */
function base64url(data) {
  let str;
  if (data instanceof Uint8Array) {
    str = String.fromCharCode(...data);
  } else {
    str = typeof data === "string" ? data : JSON.stringify(data);
  }
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Base64url decode back to string.
 */
function base64urlDecode(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return atob(padded);
}

/**
 * Sign a message with HMAC-SHA256 using the Web Crypto API.
 * This is the cryptographic signature inside the JWT.
 */
async function hmacSign(message) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(JWT_SECRET);
  const msgData = encoder.encode(message);

  const key = await crypto.subtle.importKey(
    "raw", keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, msgData);
  return new Uint8Array(signature);
}

/**
 * Verify an HMAC-SHA256 signature.
 */
async function hmacVerify(message, signatureBytes) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(JWT_SECRET);
  const msgData = encoder.encode(message);

  const key = await crypto.subtle.importKey(
    "raw", keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  return crypto.subtle.verify("HMAC", key, signatureBytes, msgData);
}

/**
 * Generate a JWT certificate after a file is registered on blockchain.
 *
 * The JWT contains:
 *   HEADER:  algorithm (HS256) and token type
 *   PAYLOAD: all registration details (hash, wallet, label, tx, block, timestamp)
 *   SIGNATURE: HMAC-SHA256 of header.payload — proves the token was not tampered with
 *
 * @param {object} params - Registration details
 * @returns {Promise<string>} - JWT token string (3 parts separated by dots)
 */
export async function generateJWT({ hash, label, walletAddress, txHash, blockNumber, ecdsaSignature }) {
  // Header: identifies this as a JWT using HMAC-SHA256
  const header = {
    alg: "HS256",        // Algorithm: HMAC-SHA256
    typ: "JWT",          // Type: JSON Web Token
    ver: "DataIntegrity-v4"
  };

  const now = Math.floor(Date.now() / 1000);

  // Payload: the claims — what this token certifies
  const payload = {
    // Standard JWT claims
    iss: "DataIntegrity-dApp",          // Issuer
    iat: now,                            // Issued at (Unix timestamp)
    exp: now + (365 * 24 * 60 * 60),   // Expires in 1 year
    jti: crypto.randomUUID(),            // Unique token ID

    // Custom claims — our file registration data
    sub:          hash,                  // Subject = file hash
    fileHash:     hash,                  // SHA-256 hash of the file
    label:        label,                 // Human-readable label
    registrant:   walletAddress,         // Ethereum wallet address
    network:      "Sepolia Testnet",     // Blockchain network
    chainId:      SEPOLIA_CHAIN_ID,
    txHash:       txHash,                // Blockchain transaction hash
    blockNumber:  blockNumber,           // Block where it was stored
    ecdsaSignature: ecdsaSignature,      // MetaMask ECDSA signature
    contractAddress: CONTRACT_ADDRESS,
  };

  // Build the unsigned token: base64url(header) + "." + base64url(payload)
  const headerEncoded  = base64url(JSON.stringify(header));
  const payloadEncoded = base64url(JSON.stringify(payload));
  const unsigned = `${headerEncoded}.${payloadEncoded}`;

  // Sign with HMAC-SHA256
  const signatureBytes = await hmacSign(unsigned);
  const signatureEncoded = base64url(signatureBytes);

  // Final JWT: header.payload.signature
  return `${unsigned}.${signatureEncoded}`;
}

/**
 * Verify a JWT token — check that it was not tampered with and extract claims.
 *
 * @param {string} token - The JWT string to verify
 * @returns {Promise<{valid: boolean, payload: object|null, error: string|null}>}
 */
export async function verifyJWT(token) {
  try {
    const parts = token.trim().split(".");
    if (parts.length !== 3) {
      return { valid: false, payload: null, error: "Invalid JWT format — must have 3 parts separated by dots" };
    }

    const [headerEncoded, payloadEncoded, signatureEncoded] = parts;
    const unsigned = `${headerEncoded}.${payloadEncoded}`;

    // Decode signature
    const sigDecoded = base64urlDecode(signatureEncoded);
    const signatureBytes = new Uint8Array(sigDecoded.length);
    for (let i = 0; i < sigDecoded.length; i++) {
      signatureBytes[i] = sigDecoded.charCodeAt(i);
    }

    // Verify HMAC-SHA256 signature
    const valid = await hmacVerify(unsigned, signatureBytes);
    if (!valid) {
      return { valid: false, payload: null, error: "JWT signature is INVALID — token may have been tampered with" };
    }

    // Decode payload
    const payloadStr = base64urlDecode(payloadEncoded);
    const payload = JSON.parse(payloadStr);

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return { valid: false, payload, error: "JWT token has expired" };
    }

    return { valid: true, payload, error: null };

  } catch (e) {
    return { valid: false, payload: null, error: "JWT parsing failed: " + e.message };
  }
}

/**
 * Download a JWT token as a .jwt file.
 * @param {string} token - The JWT string
 * @param {string} label - Used for the filename
 */
export function downloadJWT(token, label) {
  const filename = (label || "certificate").replace(/[^a-z0-9]/gi, "_") + ".jwt";
  const blob = new Blob([token], { type: "application/jwt" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── AES-256-GCM Encryption ───────────────────────────────────────────────────

export async function generateEncryptionKey() {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
  const exported = await crypto.subtle.exportKey("raw", key);
  const keyArray = Array.from(new Uint8Array(exported));
  return btoa(String.fromCharCode(...keyArray));
}

async function importKey(base64Key) {
  const keyBytes = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "raw", keyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

export async function encryptFile(file, base64Key = null) {
  const fileBytes = await file.arrayBuffer();
  const keyString = base64Key || await generateEncryptionKey();
  const cryptoKey = await importKey(keyString);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, fileBytes);
  const encryptedBlob = new Blob([encryptedBuffer], { type: "application/octet-stream" });
  const ivBase64 = btoa(String.fromCharCode(...iv));
  return { encryptedBlob, ivBase64, keyBase64: keyString, originalName: file.name, originalType: file.type };
}

export async function decryptFile(encryptedFile, base64Key, ivBase64, originalName, originalType) {
  const encryptedBytes = await encryptedFile.arrayBuffer();
  const cryptoKey = await importKey(base64Key);
  const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
  const decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, encryptedBytes);
  return new File([decryptedBuffer], originalName, { type: originalType });
}

export async function encryptAndRegisterFile(file, label, signer, ethers) {
  const encResult = await encryptFile(file);
  const encryptedBuffer = await encResult.encryptedBlob.arrayBuffer();
  const hash = await hashBuffer(encryptedBuffer);
  const { signature, message } = await signFileHash(hash, label + " [AES-256 encrypted]", signer);
  const contract = await getWritableContract(signer, ethers);
  const tx = await contract.registerHash(hash, label + " [AES-256 encrypted]", signature, message);
  const receipt = await tx.wait();
  return {
    hash, signature, tx, receipt,
    keyBase64: encResult.keyBase64,
    ivBase64: encResult.ivBase64,
    encryptedBlob: encResult.encryptedBlob,
    originalName: encResult.originalName,
  };
}

// ─── Digital signature ────────────────────────────────────────────────────────

export async function signFileHash(hash, label, signer) {
  const message = [
    "DataIntegrity — File Registration",
    "File hash: " + hash,
    "Label: " + label,
    "I certify this file is authentic and unmodified.",
    "Signed at: " + new Date().toISOString()
  ].join("\n");
  const signature = await signer.signMessage(message);
  return { signature, message };
}

// ─── Contract interactions ────────────────────────────────────────────────────

export async function registerFile(file, label, signer, ethers) {
  const hash = await hashFile(file);
  const { signature, message } = await signFileHash(hash, label, signer);
  const contract = await getWritableContract(signer, ethers);
  const tx = await contract.registerHash(hash, label, signature, message);
  const receipt = await tx.wait();
  return { hash, signature, message, tx, receipt };
}

export async function verifyFile(file) {
  const hash = await hashFile(file);
  const contract = await getReadOnlyContract();
  const [exists, registrant, timestamp, label] = await contract.verifyHash(hash);
  return {
    hash, exists, registrant,
    timestamp: exists ? new Date(Number(timestamp) * 1000) : null,
    label,
  };
}

export async function verifySignatureOnChain(hash) {
  const contract = await getReadOnlyContract();
  const [valid, recoveredSigner, expectedSigner] = await contract.verifySignature(hash);
  return { valid, recoveredSigner, expectedSigner };
}

export async function revokeHash(hash, signer, ethers) {
  const contract = await getWritableContract(signer, ethers);
  const tx = await contract.revokeHash(hash);
  return tx.wait();
}

export async function getRecordsByAddress(address) {
  const contract = await getReadOnlyContract();
  const hashes = await contract.getHashesByAddress(address);
  const records = await Promise.all(
    hashes.map(async (hash) => {
      try {
        const rec = await contract.getRecord(hash);
        return {
          hash,
          registrant: rec.registrant,
          timestamp: new Date(Number(rec.timestamp) * 1000),
          label: rec.label,
          hasSignature: rec.signature && rec.signature !== "0x",
        };
      } catch { return null; }
    })
  );
  return records.filter(Boolean);
}

export async function getTotalRecords() {
  const contract = await getReadOnlyContract();
  const total = await contract.totalRecords();
  return Number(total);
}

// ─── Etherscan helpers ────────────────────────────────────────────────────────

export function etherscanTxUrl(txHash) {
  return `https://sepolia.etherscan.io/tx/${txHash}`;
}

export function etherscanAddressUrl(address) {
  return `https://sepolia.etherscan.io/address/${address}`;
}