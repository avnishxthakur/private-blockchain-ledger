# 🔗 Private Blockchain Ledger

A private blockchain ledger built in Python to demonstrate practical cryptographic principles — data integrity, immutability, and non-repudiation — using SHA-256 hashing and ECDSA digital signatures.

Built as a project for a Data Encryption & Network Security knowledge showcase .

---

## 📌 Overview

This project implements a simplified but technically accurate blockchain ledger. Each block is cryptographically linked to the one before it, and every entry is digitally signed. Tampering with any block — even a single character — breaks the chain and is instantly detectable through cascading validation failures.

---

## ✨ Features

- 🔐 **SHA-256 Hashing** — every block's hash is a unique digital fingerprint of its contents
- ⛓️ **Cryptographic Chain Linkage** — each block stores the hash of its predecessor, forming a verifiable "chain of trust"
- 🚨 **Cascade Tamper Detection** — modifying one block automatically invalidates every block after it
- ✍️ **ECDSA Digital Signatures** (secp256k1 curve) — every block is signed for authenticity and non-repudiation
- 🧮 **Full-Chain Validation** — walks the entire chain checking hash integrity, chain linkage, and signature validity
- 🎯 **Birthday Attack Awareness Demo** — illustrates collision resistance concepts with a scaled-down toy hash

---

## 🛠️ Tech Stack

| Component | Purpose |
|---|---|
| Python 3 | Core language |
| `hashlib` (SHA-256) | Block hashing |
| `ecdsa` (secp256k1) | Digital signatures |
| `json` | Deterministic block serialization |

---

## 📁 Project Structure

```
private-blockchain-ledger/
│
├── ledger.py              # Core Block and Blockchain classes
├── test_blockchain.py     # Demo: builds a chain, validates it, simulates tampering
├── requirements.txt       # Project dependencies
└── README.md
```

---

## ⚙️ Installation & Setup

```bash
git clone https://github.com/avnishxthakur/private-blockchain-ledger.git
cd private-blockchain-ledger
pip install -r requirements.txt
```

**requirements.txt**
```
ecdsa
```

---

## 🚀 Usage

Run the demonstration script:

```bash
python test_blockchain.py
```

This runs four scenarios:
1. **Builds a chain** — generates an ECDSA key pair and adds several signed transaction blocks
2. **Validates the pristine chain** — confirms all hashes, links, and signatures check out
3. **Simulates tampering** — forges data in one block and shows the cascade failure across all downstream blocks
4. **Birthday Attack awareness demo** — illustrates why SHA-256's 256-bit output makes collision attacks computationally infeasible

---

## 🧠 How It Works

1. **Block Creation** — each block stores an index, timestamp, transaction data, the previous block's hash, and an ECDSA signature over `(data + previous_hash)`
2. **Hashing** — block fields are serialized to canonical JSON and hashed with SHA-256, producing a hash that commits to every field including the signature
3. **Chain Validation** — walking the chain re-checks three things per block: hash integrity, correct linkage to the prior block's hash, and a valid ECDSA signature
4. **Tamper Detection** — because each block's hash depends on the previous block's hash, altering any block breaks the hash of every block after it — the "cascade effect"

---

## 📊 Tested Performance

Benchmarked on a 1,000-block chain:

| Metric | Result |
|---|---|
| Avg. block creation time (hash + sign) | ~0.45 ms/block |
| Full-chain validation (1,001 blocks) | ~424 ms total |
| Signature verification throughput | ~2,500 verifications/sec |
| Tamper detection | Instant — correctly flags all downstream blocks |

---

## 👨‍💻 Author

**Avnish Thakur**
BTech CSE — Cloud Computing and Blockchain
