
import hashlib
import json
import time
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
 
 
# UTILITY — Key Generation
def generate_keypair():
    """
    Generate an ECDSA private/public key pair on the secp256k1 curve
 
    Returns
        signing_key : SigningKey — keep this SECRET (private key)
        verifying_key : VerifyingKey — share this openly (public key)
    """
    signing_key = SigningKey.generate(curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    return signing_key, verifying_key
 
 
def sign_data(signing_key: SigningKey, data: str) -> bytes:
    """
    Sign an arbitrary string with the private key.
    The data is first UTF-8 encoded so the ECDSA library
    receives raw bytes. The returned signature is also bytes.
    """
    return signing_key.sign(data.encode("utf-8"))
 
 
def verify_signature(verifying_key: VerifyingKey, data: str, signature: bytes) -> bool:
    """
    Verify a signature against the original data using the public key.
    Returns True if valid, False if tampered or wrong key.
    Catching BadSignatureError keeps the API clean — callers get a bool.
    """
    try:
        verifying_key.verify(signature, data.encode("utf-8"))
        return True
    except BadSignatureError:
        return False
 
 
# BLOCK CLASS
class Block:
    """
    A single block in the chain.
 
    Attributes
    ----------
    index : int — Position of this block (0 = Genesis)
    timestamp : float — Unix epoch at creation time
    data : str — The transaction / payload text
    previous_hash : str — SHA-256 hash of the preceding block
    signature : bytes — ECDSA signature over (data + previous_hash)
    hash : str — This block's own SHA-256 hash (computed last)
    """
 
    def __init__(
        self,
        index: int,
        data: str,
        previous_hash: str,
        signing_key: SigningKey,
    ):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
 
        # ── Digital Signature ──────────────────────────────
        # We sign (data + previous_hash) together so that
        # any change to EITHER field breaks the signature,
        # giving us both Authenticity and Non-repudiation.
        self.signature = sign_data(signing_key, self.data + self.previous_hash)
 
        # ── Block Hash ────────────────────────────────────
        # Computed AFTER the signature so that the hash
        # commits to all fields including the signature bytes.
        self.hash = self.compute_hash()
 
    # ── Core hashing logic ────────────────────────────────
    def compute_hash(self) -> str:
        """
        Serialize all block fields into a canonical JSON string,
        then return its SHA-256 hex digest.
 
        Why JSON? It gives a deterministic, human-readable byte
        sequence — no floating-point or ordering surprises.
 
        Why include previous_hash? This is what creates the
        *chain*: each block's hash depends on its parent's hash,
        so altering any ancestor invalidates all descendants.
        """
        block_dict = {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            # Encode signature as hex so JSON can serialize it
            "signature": self.signature.hex(),
        }
        block_string = json.dumps(block_dict, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
 
    def __repr__(self) -> str:
        return (
            f"Block(index={self.index}, "
            f"hash={self.hash[:12]}…, "
            f"prev={self.previous_hash[:12]}…)"
        )
 
 
# BLOCKCHAIN CLASS
class Blockchain:
    """
    An ordered, immutable ledger of Block objects.
    The first block (index 0) is the *Genesis Block* whose
    previous_hash is the string "0" by convention.
    """
 
    GENESIS_PREV_HASH = "0" * 64  # 64 zeros — a placeholder
 
    def __init__(self, signing_key: SigningKey):
        self.signing_key = signing_key
        self.chain: list[Block] = []
        self._create_genesis_block()
 
    # ── Internal helpers ──────────────────────────────────
    def _create_genesis_block(self):
        """Bootstrap the chain with a hard-coded Genesis Block."""
        genesis = Block(
            index=0,
            data="Genesis Block — Origin of the Chain",
            previous_hash=self.GENESIS_PREV_HASH,
            signing_key=self.signing_key,
        )
        self.chain.append(genesis)
 
    @property
    def last_block(self) -> Block:
        return self.chain[-1]
 
    # ── Public API ────────────────────────────────────────
    def add_block(self, data: str) -> Block:
        """
        Append a new block whose previous_hash links to the
        current tail of the chain.
        """
        new_block = Block(
            index=len(self.chain),
            data=data,
            previous_hash=self.last_block.hash,
            signing_key=self.signing_key,
        )
        self.chain.append(new_block)
        return new_block
 
    def validate_chain(self, verifying_key: VerifyingKey) -> tuple[bool, list[str]]:
        """
        Walk the entire chain performing THREE checks on each block:
          1. Hash integrity — recompute the hash and compare.
          2. Chain linkage — previous_hash must equal the prior block's hash.
          3. Signature check — verify the ECDSA signature with the public key.
 
        Returns
        -------
        (is_valid : bool, errors : list[str])
        is_valid is True only when errors is empty.
        """
        errors: list[str] = []
 
        for i, block in enumerate(self.chain):
            # ── Check 1: Hash integrity ────────────────────
            recomputed = block.compute_hash()
            if recomputed != block.hash:
                errors.append(
                    f"[Block {i}] Hash MISMATCH — stored={block.hash[:16]}… "
                    f"recomputed={recomputed[:16]}…"
                )
 
            # ── Check 2: Chain linkage ─────────────────────
            if i > 0:
                expected_prev = self.chain[i - 1].hash
                if block.previous_hash != expected_prev:
                    errors.append(
                        f"[Block {i}] Broken link — previous_hash does not "
                        f"match Block {i-1}'s hash."
                    )
 
            # ── Check 3: Digital signature ─────────────────
            sig_valid = verify_signature(
                verifying_key,
                block.data + block.previous_hash,
                block.signature,
            )
            if not sig_valid:
                errors.append(
                    f"[Block {i}] INVALID signature — data may be forged or "
                    f"signed by a different key."
                )
 
        return (len(errors) == 0), errors
