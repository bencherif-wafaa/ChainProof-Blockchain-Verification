# ChainProof-Blockchain-Verification
Blockchain file verification system — SHA-256 + ECDSA + AES-256 + JWT + Ethereum Sepolia
# DataIntegrity — Blockchain Fake Data Prevention

Decentralized system to detect and prevent fake/tampered data using SHA-256 cryptographic hashing + Ethereum blockchain (Sepolia testnet).

## How it works

1. User uploads a file → SHA-256 hash computed client-side
2. Hash stored on-chain via `DataIntegrity.sol` (Sepolia)
3. To verify: re-hash the file, query the contract
4. If hashes match → authentic. If different → tampered.

---

## Project structure

```
blockchain-integrity/
├── contracts/
│   └── DataIntegrity.sol      ← Solidity smart contract
├── frontend/
│   ├── index.html             ← Complete web application
│   └── blockchain.js          ← Ethers.js integration module
├── scripts/
│   └── deploy.js              ← Hardhat deployment script
├── hardhat.config.js
├── package.json
└── .env.example               ← Copy to .env and fill in keys
```

---

## Setup

### 1 — Prerequisites

- Node.js v18 or later: https://nodejs.org
- MetaMask browser extension: https://metamask.io
- Sepolia testnet ETH (free): https://sepoliafaucet.com

### 2 — Install dependencies

```bash
npm install
```

### 3 — Configure environment

```bash
cp .env.example .env
```

Edit `.env` and fill in:

| Variable           | Where to get it |
|--------------------|----------------|
| `PRIVATE_KEY`      | MetaMask → Account → Export Private Key |
| `SEPOLIA_RPC_URL`  | [Alchemy](https://alchemy.com) or [Infura](https://infura.io) (free tier) |
| `ETHERSCAN_API_KEY`| [Etherscan](https://etherscan.io/myapikey) (optional, for verification) |

> **Security:** Never commit `.env` to git. Add it to `.gitignore`.

---

## Deploy the contract

### Compile

```bash
npm run compile
```

### Deploy to Sepolia

```bash
npm run deploy
```

You will see output like:
```
Contract deployed!
Address:   0xAbCd1234...
Etherscan: https://sepolia.etherscan.io/address/0xAbCd1234...
```

### Update the frontend

Open `frontend/blockchain.js` and replace:

```js
export const CONTRACT_ADDRESS = "0xYOUR_CONTRACT_ADDRESS_HERE";
```

with your deployed address.

### (Optional) Verify on Etherscan

```bash
npx hardhat verify --network sepolia <CONTRACT_ADDRESS>
```

---

## Run the frontend

```bash
npm run serve
```

Open `http://localhost:3000` in your browser.

You can also open `frontend/index.html` directly in the browser — it works without a server for most operations (MetaMask required for write transactions).

---

## Smart contract reference

### `registerHash(bytes32 hash, string label)`
Store a file hash on-chain. Emits `HashRegistered`.

### `verifyHash(bytes32 hash)`
Check if a hash exists. Returns `(exists, registrant, timestamp, label)`.

### `revokeHash(bytes32 hash)`
Remove a hash you previously registered. Only the original registrant can revoke.

### `getHashesByAddress(address)`
Get all hashes registered by a given address.

### `totalRecords()`
Total number of active records on-chain.

---

## Security notes

- SHA-256 is collision-resistant — it is computationally infeasible to produce a different file with the same hash.
- The blockchain guarantees immutability and timestamping — records cannot be retroactively modified.
- The contract uses custom errors for gas efficiency.
- Hashes are stored as `bytes32` (not strings) to save gas.
- Only the original registrant can revoke their own records.

---

## Gas estimates (Sepolia)

| Operation      | Approximate gas |
|----------------|----------------|
| `registerHash` | ~65,000 gas    |
| `revokeHash`   | ~35,000 gas    |
| `verifyHash`   | ~0 (read only) |

On Sepolia, testnet ETH is free — gas costs nothing real during development.

---

## Technologies

| Technology | Role |
|-----------|------|
| Solidity 0.8.20 | Smart contract |
| Ethers.js v6 | Frontend ↔ blockchain bridge |
| SHA-256 (Web Crypto API) | Cryptographic hashing |
| Ethereum Sepolia | Test blockchain network |
| Etherscan | Transaction transparency |
| Hardhat | Compilation & deployment |
| MetaMask | User wallet |
