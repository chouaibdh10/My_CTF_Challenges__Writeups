# HBU BSides - IPv6 Hop-by-Hop Challenge

Category: Network Forensics  
Date: 2025-12-21  
Tools: Wireshark, `tshark`, Python

## Challenge Description

ICMPv6 Echo Request packets contain IPv6 Hop-by-Hop `PadN` option bytes carrying hidden data.

The hidden message is encrypted and split across packets:

1. Reassemble `PadN` bytes
2. XOR-decrypt
3. Base64-decode

## Method Summary

1. Filter packets with relevant options and identifier.
2. Sort by ICMPv6 sequence number.
3. Recover XOR key using known plaintext:
   `0x21 XOR 0x63 = 0x42`.
4. XOR every byte with `0x42`.
5. Concatenate to full Base64 string and decode.

## Flag

`shellmates{h0p_by_h0p_0pt10ns_h1d3_s3cr3ts_1n_pl41n_s1ght}`

## Key Takeaways

1. Hop-by-Hop options can be abused as covert channels.
2. Known-plaintext attacks can recover XOR keys quickly.
3. Unusual protocol fields deserve focused inspection.
