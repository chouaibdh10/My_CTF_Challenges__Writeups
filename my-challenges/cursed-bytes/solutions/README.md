
## Ground truth
- DNS C2: `5.182.33.151:53`
- Exfil domain marker/suffix: `txn.sync-bdh-payables.com`
- Base XOR key: `st1k4`
- Seed hidden in HTML comment: `<!-- campaign-tag: QkRILVJBTlNPTS1TVEFHRTI= -->`
- Derived XOR key (hex): `2f55ad4fed37c5a1`
- Payload transform: `json -> zlib -> XOR -> hex`
- Expected flag: `nexus{hacker_strongest_secret_is_a_stenographer}`

## Solving chain
1. Parse `email(1).eml`, recover campaign tag from HTML comments and decode base64 seed.
2. Parse DNS queries to `5.182.33.151` and isolate names under `*.txn.sync-bdh-payables.com`.
3. Rebuild hex payloads from query labels and keep valid hex blobs.
4. Decrypt each blob with derived XOR key, then zlib decompress.
5. Parse JSON records (`c`, `t`), burst-group by short time windows.
6. Keep longest chord per burst, translate steno chords, resolve meta tokens.

