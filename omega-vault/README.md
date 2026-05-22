# Omega Vault

Category: Cryptography  
Difficulty: Hard  
Artifact: `vault_bundle.json`

## Challenge Description

Recover vault key material from three linked stages:

1. Faulted RSA-CRT signature transcript
2. Corrupted Shamir secret shares
3. Encrypted vault payload

## Stage 1 - Bellcore Attack on RSA-CRT

Use:

```text
g = gcd(sig_good - sig_fault, n)
```

If `g` is non-trivial, recover `p = g` and `q = n / p`.

## Stage 2 - Shamir Recovery with Errors

Treat shares as a noisy Reed-Solomon problem and apply Berlekamp-Welch:

1. Build `Q(x) = P(x)E(x)`
2. Solve linear system over finite field
3. Divide `Q` by `E` to recover `P`
4. Extract secret `seed_b = P(0)`

## Stage 3 - Final Decryption

1. Derive `seed_a = SHA256("p:q")[:16]`
2. Derive `master_key = SHA256(seed_a || seed_b)`
3. Regenerate keystream blocks with `SHA256(master_key || nonce || counter)`
4. XOR with ciphertext to recover plaintext flag

## Flag

`nexus{crt_faults_rs_decoding_and_hybrid_key_fusion_omega}`

## Extra

- Full official explanation: `./solution/README.md`
- Solver script: `./solution/solve.py`
