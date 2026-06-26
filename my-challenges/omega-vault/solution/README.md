# 🧩 Official Writeup — OMEGA VAULT

## Overview

The artifact `vault_bundle.json` implements a 3-stage cryptographic challenge:

1. Bellcore-style fault attack on RSA-CRT signatures  
2. Reconstruction of a Shamir secret with corrupted shares  
3. Key derivation + stream cipher decryption  

---

# 🔐 Stage 1 — Recover RSA factors via faulted CRT signature

Given:

- modulus `n`
- correct signature `sig_good`
- faulted signature `sig_fault`

Under RSA-CRT fault conditions, one CRT branch is correct while the other is corrupted. This allows recovery of a factor of `n`.

### Key idea:

\[
g = \gcd(sig\_good - sig\_fault,\ n)
\]

If:

- `g ≠ 1`
- `g ≠ n`

Then:

- `p = g`
- `q = n / p`

This is a **Bellcore fault attack** exploiting CRT signature leakage.

---

# 🧠 Stage 2 — Recover Shamir secret with corrupted shares

Inputs:

- Prime field \( \mathbb{F}_p \)
- Threshold \( k \)
- \( n \) shares
- Up to 5 shares may be corrupted

We interpret the system as a noisy Reed–Solomon code.

## Berlekamp–Welch decoding

We construct:

- \( P(x) \): secret polynomial (deg < k)
- \( E(x) \): error locator polynomial (monic, deg ≤ e)
- \( Q(x) = P(x)E(x) \)

such that:

\[
Q(x_i) = y_i \cdot E(x_i)
\]

for all provided points.

## Procedure:

1. Try error count \( e = 0 \rightarrow 5 \)
2. Build linear system over \( \mathbb{F}_p \)
3. Solve for coefficients of \( Q \) and \( E \)
4. Recover:
   \[
   P(x) = \frac{Q(x)}{E(x)}
   \]
5. Extract secret:
   \[
   seed_b = P(0)
   \]

Result: 16-byte secret seed.

---

# 🔑 Stage 3 — Vault decryption

## Key derivation

\[
seed_a = SHA256(\text{str}(p) : \text{str}(q))[:16]
\]

\[
master\_key = SHA256(seed_a \parallel seed_b)
\]

---

## Stream cipher

For each block \( i \):

\[
keystream_i = SHA256(master\_key \parallel nonce \parallel i)
\]

\[
plaintext_i = ciphertext_i \oplus keystream_i
\]

---

## Final output

Concatenate all plaintext blocks to obtain:
nexus{crt_faults_rs_decoding_and_hybrid_key_fusion_omega}

