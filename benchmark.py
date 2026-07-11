import time
import statistics
from ledger import Blockchain, generate_keypair, verify_signature

print("=" * 60)
print("BENCHMARK 1: Block creation speed (hash + ECDSA sign)")
print("=" * 60)

private_key, public_key = generate_keypair()
bc = Blockchain(signing_key=private_key)

N = 1000
times = []
for i in range(N):
    t0 = time.perf_counter()
    bc.add_block(f"Transaction {i}: Alice -> Bob : {i} tokens")
    t1 = time.perf_counter()
    times.append((t1 - t0) * 1000)  # ms

print(f"Blocks added: {N}")
print(f"Avg block creation time: {statistics.mean(times):.3f} ms")
print(f"Median: {statistics.median(times):.3f} ms")
print(f"Min/Max: {min(times):.3f} / {max(times):.3f} ms")
print(f"Chain length after test: {len(bc.chain)} blocks")

print()
print("=" * 60)
print("BENCHMARK 2: Full chain validation speed")
print("=" * 60)

t0 = time.perf_counter()
valid, errors = bc.validate_chain(public_key)
t1 = time.perf_counter()
validation_time_ms = (t1 - t0) * 1000

print(f"Validated {len(bc.chain)} blocks (hash + link + signature checks)")
print(f"Chain valid: {valid}")
print(f"Total validation time: {validation_time_ms:.2f} ms")
print(f"Avg per block: {validation_time_ms/len(bc.chain):.3f} ms")

print()
print("=" * 60)
print("BENCHMARK 3: Tamper detection (cascade effect)")
print("=" * 60)

# Tamper with a block roughly in the middle
tamper_index = len(bc.chain) // 2
original_data = bc.chain[tamper_index].data
bc.chain[tamper_index].data = "FORGED ENTRY"

t0 = time.perf_counter()
valid, errors = bc.validate_chain(public_key)
t1 = time.perf_counter()
detection_time_ms = (t1 - t0) * 1000

print(f"Tampered block index: {tamper_index} (of {len(bc.chain)-1})")
print(f"Chain detected as invalid: {not valid}")
print(f"Number of violations detected: {len(errors)}")
print(f"Detection time: {detection_time_ms:.2f} ms")
print(f"Blocks affected by cascade (downstream of tamper point): {len(bc.chain) - tamper_index}")

# restore
bc.chain[tamper_index].data = original_data

print()
print("=" * 60)
print("BENCHMARK 4: Signature verification throughput")
print("=" * 60)

sig_times = []
for block in bc.chain[:200]:
    t0 = time.perf_counter()
    verify_signature(public_key, block.data + block.previous_hash, block.signature)
    t1 = time.perf_counter()
    sig_times.append((t1 - t0) * 1000)

print(f"Signatures verified: {len(sig_times)}")
print(f"Avg verification time: {statistics.mean(sig_times):.3f} ms")
print(f"Verifications/sec (single-threaded): {1000/statistics.mean(sig_times):.0f}")

print()
print("=" * 60)
print("BENCHMARK 5: SHA-256 collision resistance context")
print("=" * 60)
print("256-bit hash space => birthday-bound collision resistance ~2^128 operations")
print("(theoretical, not brute-forced here - infeasible by design)")
