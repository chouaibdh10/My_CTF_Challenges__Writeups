#!/usr/bin/env python3
"""
Official solver for NEXUS OMEGA VAULT.

Solve chain:
1) Recover RSA factors from Bellcore-style CRT fault
2) Recover Shamir secret with corrupted shares via Berlekamp-Welch
3) Derive final key and decrypt vault envelope
"""

import hashlib
import json
import math
import sys
from typing import List, Optional, Tuple


DEFAULT_FILE = "vault_bundle.json"


def xor_stream(key: bytes, nonce: bytes, data: bytes) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        stream.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, stream[:len(data)]))


def poly_trim(poly: List[int]) -> List[int]:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_eval(coeffs: List[int], x: int, mod: int) -> int:
    acc = 0
    power = 1
    for c in coeffs:
        acc = (acc + c * power) % mod
        power = (power * x) % mod
    return acc


def poly_divmod(num: List[int], den: List[int], mod: int) -> Tuple[List[int], List[int]]:
    num = poly_trim(num[:])
    den = poly_trim(den[:])
    if len(den) == 1 and den[0] == 0:
        raise ZeroDivisionError("polynomial division by zero")

    if len(num) < len(den):
        return [0], num

    q = [0] * (len(num) - len(den) + 1)
    inv_lead = pow(den[-1], -1, mod)

    while len(num) >= len(den):
        shift = len(num) - len(den)
        coef = (num[-1] * inv_lead) % mod
        q[shift] = coef
        for i in range(len(den)):
            num[shift + i] = (num[shift + i] - coef * den[i]) % mod
        num = poly_trim(num)

    return poly_trim(q), poly_trim(num)


def solve_linear_mod(matrix: List[List[int]], rhs: List[int], mod: int) -> Optional[List[int]]:
    """Solve A x = b (mod mod) with Gaussian elimination on augmented matrix."""
    if not matrix:
        return []

    m = len(matrix)
    n = len(matrix[0])
    aug = [row[:] + [rhs[i] % mod] for i, row in enumerate(matrix)]

    pivot_cols = []
    r = 0
    for c in range(n):
        pivot = None
        for rr in range(r, m):
            if aug[rr][c] % mod != 0:
                pivot = rr
                break
        if pivot is None:
            continue

        aug[r], aug[pivot] = aug[pivot], aug[r]

        inv = pow(aug[r][c], -1, mod)
        for cc in range(c, n + 1):
            aug[r][cc] = (aug[r][cc] * inv) % mod

        for rr in range(m):
            if rr == r:
                continue
            factor = aug[rr][c] % mod
            if factor == 0:
                continue
            for cc in range(c, n + 1):
                aug[rr][cc] = (aug[rr][cc] - factor * aug[r][cc]) % mod

        pivot_cols.append((r, c))
        r += 1
        if r == m:
            break

    # Check consistency
    for rr in range(m):
        if all(aug[rr][cc] % mod == 0 for cc in range(n)) and aug[rr][n] % mod != 0:
            return None

    # Back-substitute with free variables fixed to zero
    x = [0] * n
    for rr, c in reversed(pivot_cols):
        value = aug[rr][n]
        for cc in range(c + 1, n):
            value = (value - aug[rr][cc] * x[cc]) % mod
        x[c] = value % mod

    return x


def recover_shamir_secret_with_errors(
    shares: List[Tuple[int, int]],
    threshold: int,
    field_prime: int,
    max_errors: int,
) -> Tuple[int, int]:
    """Berlekamp-Welch decode for Reed-Solomon style Shamir shares with errors."""
    n = len(shares)
    k = threshold

    for e in range(max_errors + 1):
        unknowns = (k + e) + e
        if n < unknowns:
            continue

        matrix = []
        rhs = []

        for x, y in shares:
            row = []
            # Q(x) coefficients: q_0..q_{k+e-1}
            power = 1
            for _ in range(k + e):
                row.append(power)
                power = (power * x) % field_prime

            # -y * E_low(x) coefficients: e_0..e_{e-1}
            power = 1
            for _ in range(e):
                row.append((-y * power) % field_prime)
                power = (power * x) % field_prime

            matrix.append(row)
            rhs.append((y * pow(x, e, field_prime)) % field_prime)

        sol = solve_linear_mod(matrix, rhs, field_prime)
        if sol is None:
            continue

        q_coeffs = sol[: k + e]
        e_low = sol[k + e :]
        e_coeffs = e_low + [1]  # monic: x^e + ...

        p_coeffs, rem = poly_divmod(q_coeffs, e_coeffs, field_prime)
        if any(v % field_prime != 0 for v in rem):
            continue

        if len(p_coeffs) > k:
            continue

        mismatches = 0
        for x, y in shares:
            if poly_eval(p_coeffs, x, field_prime) != y:
                mismatches += 1

        if mismatches <= e:
            return p_coeffs[0] % field_prime, mismatches

    raise ValueError("Could not decode shares with configured max errors")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FILE
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    print("=" * 72)
    print("  NEXUS OMEGA VAULT - OFFICIAL SOLVER")
    print("=" * 72)

    # Stage 1: Bellcore fault attack
    rsa = bundle["rsa_fault"]
    n = int(rsa["n"])
    sig_good = int(rsa["sig_good"])
    sig_fault = int(rsa["sig_fault"])

    factor = math.gcd(abs(sig_good - sig_fault), n)
    if factor in (1, n):
        raise ValueError("Bellcore step failed: invalid gcd factor")

    p = factor
    q = n // factor
    if p < q:
        p, q = q, p

    print("\n[1] Bellcore fault attack")
    print(f"    recovered factor bits: p={p.bit_length()}, q={q.bit_length()}")

    seed_a = hashlib.sha256(f"{p}:{q}".encode()).digest()[:16]

    # Stage 2: Berlekamp-Welch on corrupted Shamir shares
    shamir = bundle["shamir"]
    field_prime = int(shamir["field_prime"])
    threshold = int(shamir["threshold"])
    shares = [(int(x), int(y)) for x, y in shamir["shares"]]

    secret_b_int, mismatches = recover_shamir_secret_with_errors(
        shares=shares,
        threshold=threshold,
        field_prime=field_prime,
        max_errors=5,
    )

    seed_b = secret_b_int.to_bytes(16, "big")

    print("\n[2] Shamir recovery with corrupted shares")
    print(f"    decoded share mismatches: {mismatches}")
    print(f"    recovered seed_b: {seed_b.hex()}")

    # Stage 3: Decrypt vault
    vault = bundle["vault"]
    nonce = bytes.fromhex(vault["nonce_hex"])
    ciphertext = bytes.fromhex(vault["ciphertext_hex"])

    master_key = hashlib.sha256(seed_a + seed_b).digest()
    plaintext = xor_stream(master_key, nonce, ciphertext)

    print("\n[3] Vault decrypt")
    print(f"    plaintext: {plaintext.decode('utf-8', errors='replace')}")


if __name__ == "__main__":
    main()
