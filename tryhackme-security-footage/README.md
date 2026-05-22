# TryHackMe - Security Footage Recovery

Category: Forensics  
Date: 2025-11-06  
Room: `https://tryhackme.com/room/securityfootage`  
Tools: Wireshark, Foremost

## Challenge Description

An office break-in occurred and CCTV drives were destroyed.  
You receive a `.pcap` and must recover footage from captured HTTP traffic.

## Step-by-step

1. Open the capture in Wireshark and focus on HTTP packets.

2. Follow TCP streams:

`Follow -> TCP Stream`

Look for headers such as:

```text
Content-Type: image/jpeg
Content-Length: 20485
```

3. Filter JPEG-related traffic:

```text
tcp contains "jpeg"
```

4. Carve files with Foremost:

```bash
foremost -i security-footage-1648933966395.pcap -o results_folder
```

5. Inspect recovered images:

```bash
ls results_folder/jpg/
```

Example:

```text
00000000.jpg  00000001.jpg  00000002.jpg  00000003.jpg
```

## Result

Recovered multiple JPEG frames from PCAP traffic, reconstructing the CCTV footage.

## Key Takeaways

1. PCAP captures can contain full file payloads.
2. Wireshark stream analysis accelerates forensic triage.
3. Foremost is effective for automated file carving.
