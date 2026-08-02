# Silent Pulse

Category: Network Forensics  
Difficulty: Medium  
Event: ITC CTF 2026  
Author: Chouaibdh  
Artifact: `silent_pulse.pcap`

## Challenge Description

The SOC detected unusual outbound connections from the finance VLAN. A packet
capture covering the suspected incident window is provided. Investigators think
one workstation downloaded a malicious-looking file and began communicating
with command-and-control infrastructure.

## Objectives

1. Identify the compromised workstation IP and hostname.
2. Identify the C2 domain, IP address, and port.
3. Determine the approximate beacon interval in seconds.
4. Recover and decode the commands sent by the C2 server.
5. Identify the exfiltrated file and recover the flag inside it.

## Flag Format

Submit the answers in this order:

```text
itc{ip_hostname_c2-domain_c2-ip:port_interval_session-key_filename_embedded-flag}
```

## Solution Outline

1. Triage DNS and HTTP traffic to locate a suspicious double-extension download.
2. Correlate the victim's DNS lookups with recurring traffic on TCP port 8080.
3. Measure the C2 request timestamps to determine the beacon interval.
4. Decode the DNS TXT value and Base64-encoded tasking.
5. Reassemble the HTTP upload, then apply Base64 decoding and repeating-key XOR.

## Files

- Challenge capture: [`challenge/silent_pulse.pcap`](./challenge/silent_pulse.pcap)
- Full official writeup: [`solution/README.md`](./solution/README.md)
- Decoding result screenshot: [`solution/image.webp`](./solution/image.webp)

## Final Answer

```text
itc{10.10.20.15_WS-FIN-07_updates-cdn.example_198.51.100.77:8080_30s_NOCTURNE_merger_notes.txt_itc{silent_pulse_http_c2_exfil}}
```
