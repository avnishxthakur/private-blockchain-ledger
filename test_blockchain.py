"""
test_blockchain.py — Demonstration & Attack Simulation

Runs four scenarios:
  1. Build a 4-block chain (Genesis + 3 transactions)
  2. Validate the pristine chain → PASS
  3. Tamper with Block 1's data → trigger cascade failure
  4. Simulate a Birthday-Attack awareness check
"""

from ledger import (
    Blockchain,
    generate_keypair,
    sign_data,
    verify_signature,
)
import hashlib, time, random, string

# ── ANSI colour helpers ────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def banner(title: str):
    width = 60
    print(f"\n{BOLD}{CYAN}{'═'*width}{RESET}")
    print(f"{BOLD}{CYAN} {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*width}{RESET}")


def ok(msg): print(f" {GREEN}✔ {msg}{RESET}")
def err(msg): print(f" {RED}✘ {msg}{RESET}")
def info(msg): print(f" {YELLOW}ℹ {msg}{RESET}")


# SCENARIO 1 — Build the chain
banner("SCENARIO 1 — Building the Blockchain")

private_key, public_key = generate_keypair()
info(f"ECDSA key-pair generated (secp256k1 curve)")
info(f"Public key (hex): {public_key.to_string().hex()[:48]}…")

bc = Blockchain(signing_key=private_key)

transactions = [
    "Alice → Bob : 50 tokens | Ref: INV-001",
    "Bob → Carol : 20 tokens | Ref: INV-002",
    "Carol → Alice : 10 tokens | Ref: INV-003",
]

for tx in transactions:
    blk = bc.add_block(tx)
    ok(f"Added Block {blk.index} hash={blk.hash[:20]}…")

print()
for blk in bc.chain:
    print(f"  [{blk.index}] {blk.data[:45]:<45} | hash: {blk.hash[:16]}…")


# SCENARIO 2 — Validate pristine chain
banner("SCENARIO 2 — Validating the Pristine Chain")

valid, errors = bc.validate_chain(public_key)
if valid:
    ok("Chain is VALID — all hashes, links, and signatures check out.")
else:
    for e in errors:
        err(e)


# SCENARIO 3 — Tamper with Block 1 (cascade effect)
banner("SCENARIO 3 — Tampering with Block 1 (Cascade Effect)")

info("Original Block 1 data : " + bc.chain[1].data)
info("Injecting forged data into Block 1 …")

# ── Simulate an adversary directly mutating the stored data.
# The adversary does NOT have the private key, so they cannot
# re-sign or recompute a valid hash chain.
bc.chain[1].data = "Alice → Mallory: 50 tokens | FORGED ENTRY!"
info("Tampered Block 1 data : " + bc.chain[1].data)

print()
valid, errors = bc.validate_chain(public_key)
if valid:
    ok("Chain is valid (this should not happen!)")
else:
    print(f" {RED}{BOLD}Chain is INVALID — {len(errors)} violation(s) detected:{RESET}")
    for e in errors:
        err(e)

print()
info("Cascade explanation:")
info("  Block 1 hash changes → Block 2's previous_hash is now wrong")
info("  Block 2 hash changes → Block 3's previous_hash is now wrong")
info("  Every block after the tampered one is invalidated automatically.")


# SCENARIO 4 — Birthday Attack Awareness
banner("SCENARIO 4 — Birthday Attack Simulation (Awareness Demo)")

info("A Birthday Attack tries to find two different inputs with the SAME hash.")
info("For SHA-256 (256-bit output), the expected work is ~2^128 operations.")
info("Running a tiny brute-force on a 16-bit toy hash to ILLUSTRATE the math…")
print()


def toy_hash(s: str, bits: int = 16) -> str:
    """Truncate SHA-256 to `bits` bits for demonstration only."""
    full = hashlib.sha256(s.encode()).hexdigest()
    # Keep only the first (bits//4) hex chars
    return full[: bits // 4]


# Attempt to find any collision in a 16-bit space
seen: dict[str, str] = {}
attempts = 0
collision_found = False
target_bits = 16

while attempts < 200_000:
    candidate = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    h = toy_hash(candidate, target_bits)
    attempts += 1
    if h in seen and seen[h] != candidate:
        ok(f"Collision found after {attempts:,} attempts (16-bit toy hash)!")
        ok(f"  Input A : '{seen[h]}' → hash: {h}")
        ok(f"  Input B : '{candidate}' → hash: {h}")
        collision_found = True
        break
    seen[h] = candidate

if not collision_found:
    info("No collision found in 200,000 attempts (unlikely but possible).")

print()
info("SHA-256 defence: 256-bit output makes birthday attacks computationally")
info("infeasible. You would need ~2^128 ≈ 3.4 × 10^38 attempts on average.")
info("Current fastest supercomputers would take longer than the age of the universe.")

banner("END OF DEMONSTRATION")
print(f" {GREEN}{BOLD}All four scenarios completed successfully.{RESET}\n")
