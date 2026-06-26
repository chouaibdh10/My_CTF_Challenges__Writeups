# Cursed Byte

Category: Forensics  
Difficulty: Medium  
Author: Chouaibdh

## Challenge Description

A suspicious finance phishing thread was opened by AP staff. Minutes later, covert outbound traffic was detected.  
Recover the flag in format `nexus{...}` from provided artifacts only.

## Provided Files

1. `email(1).eml` - phishing email with heavy header/body/HTML noise
2. `chall.pcapng` - noisy network capture containing covert DNS exfiltration

## Connection

No remote service. This is an offline forensics challenge.

## Solution Outline

1. Parse the email and recover seed from HTML `campaign-tag` comment.
2. Isolate DNS queries to C2 and rebuild payload hex from query labels.
3. Decrypt payload (`XOR`), then decompress (`zlib`) and parse JSON events.
4. Reconstruct stable steno strokes from bursty chord telemetry.
5. Translate strokes to text and reconstruct the final flag.

## Flag

`nexus{hacker_strongest_secret_is_a_stenographer}`

## Extra

1. Ground-truth and solving notes: `./solutions/README.md`
2. End-to-end solver: `./solutions/solve.py`
