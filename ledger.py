"""
Blockchain Ledger — Data Encryption & Network Security
BTech 6th Semester Mini-Project
Modules : Block, Blockchain, Digital Signatures (ECDSA)
Hashing : SHA-256 via hashlib
Signing : ECDSA (secp256k1 curve)

NOTE: adapted to use the 'cryptography' library instead of 'ecdsa'
(sandbox has no network access to pip install 'ecdsa'), but the
algorithm (ECDSA on secp256k1) and all logic is identical to the
original submitted project.
"""

import hashlib
import json
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def generate_keypair():
    signing_key = ec.generate_private_key(ec.SECP256K1())
    verifying_key = signing_key.public_key()
    return signing_key, verifying_key


def sign_data(signing_key, data: str) -> bytes:
    return signing_key.sign(data.encode("utf-8"), ec.ECDSA(hashes.SHA256()))


def verify_signature(verifying_key, data: str, signature: bytes) -> bool:
    try:
        verifying_key.verify(signature, data.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


class Block:
    def __init__(self, index: int, data: str, previous_hash: str, signing_key):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.signature = sign_data(signing_key, self.data + self.previous_hash)
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_dict = {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "signature": self.signature.hex(),
        }
        block_string = json.dumps(block_dict, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def __repr__(self) -> str:
        return f"Block(index={self.index}, hash={self.hash[:12]}..., prev={self.previous_hash[:12]}...)"


class Blockchain:
    GENESIS_PREV_HASH = "0" * 64

    def __init__(self, signing_key):
        self.signing_key = signing_key
        self.chain = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(
            index=0,
            data="Genesis Block - Origin of the Chain",
            previous_hash=self.GENESIS_PREV_HASH,
            signing_key=self.signing_key,
        )
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, data: str) -> Block:
        new_block = Block(
            index=len(self.chain),
            data=data,
            previous_hash=self.last_block.hash,
            signing_key=self.signing_key,
        )
        self.chain.append(new_block)
        return new_block

    def validate_chain(self, verifying_key):
        errors = []
        for i, block in enumerate(self.chain):
            recomputed = block.compute_hash()
            if recomputed != block.hash:
                errors.append(f"[Block {i}] Hash MISMATCH")

            if i > 0:
                expected_prev = self.chain[i - 1].hash
                if block.previous_hash != expected_prev:
                    errors.append(f"[Block {i}] Broken link")

            sig_valid = verify_signature(
                verifying_key,
                block.data + block.previous_hash,
                block.signature,
            )
            if not sig_valid:
                errors.append(f"[Block {i}] INVALID signature")

        return (len(errors) == 0), errors
