# Amadey - APT-C-36 Lab

Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/amadey-apt-c-36/

## 0. Attack Context (DFIR Mindset)

Classic investigation flow:

```text
EDR alert -> suspicious process -> memory dump analysis
```

Main reconstruction goals:

- Entry point
- Malicious process
- C2 server
- Downloaded payloads
- Persistence
- Impact

## 1. Global DFIR Methodology

Always follow this chain:

```text
1. Process Tree (pstree)
2. Command Line (cmdline)
3. Network Connections (netscan)
4. File System (filescan)
5. Memory Extraction (memmap + strings)
6. Persistence (registry / tasks / startup)
```

## Q1 - Parent Process

Tool:

```text
windows.pstree
```

Finding:

```text
lssass.exe
```

Why suspicious:

- Mimics `lsass.exe`
- Typo-squatting process name
- Common malware masquerading pattern

Answer: `lssass.exe`

## Q2 - Malware Location

Tool:

```text
windows.cmdline
```

Finding:

```text
C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe
```

Interpretation:

- `AppData\Local\Temp` is a common staging path
- Random temp folder suggests unpack/drop behavior

## Q3 - C2 Server IP

Tool:

```text
windows.netscan
```

Filter logic:

- Focus on PID for `lssass.exe`
- Look for established outbound connection

Finding:

```text
41.75.84.12
```

Interpretation:

- External command-and-control endpoint

## Q4 - Number of Downloaded Files

Tools:

```text
memmap + strings
```

Command:

```bash
strings pid.2748.dmp | grep "GET /"
```

Result:

- 2 unique HTTP GET requests

Answer: `2`

Interpretation:

- Modular delivery (loader + modules)

## Q5 - Downloaded File Path

Tools:

```text
windows.cmdline + windows.filescan
```

Finding:

```text
C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll
```

Interpretation:

- `AppData\Roaming` commonly used for persistence-related staging
- Randomized folder name helps evasion
- DLL likely used for injection or follow-on execution

## Q6 - Child Process Execution

Tool:

```text
windows.pstree
```

Finding:

```text
rundll32.exe
```

Why important:

```text
rundll32.exe malicious.dll,entrypoint
```

- Classic LOLBIN abuse
- Stealthier DLL execution path

## Q7 - Persistence Mechanism

Tool:

```text
windows.filescan
```

Findings:

```text
C:\Windows\System32\Tasks\lssass.exe
C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe
```

Interpretation:

1. Scheduled Task persistence:

```text
C:\Windows\System32\Tasks\
```

2. Temp-based fallback execution:

```text
AppData\Local\Temp\
```

## Full Attack Chain

```text
1. Execution:
   C:\Users\...\Temp\925e7e99c5\lssass.exe
2. Persistence:
   C:\Windows\System32\Tasks\lssass.exe
3. C2 Communication:
   41.75.84.12
4. Download Stage:
   2 GET requests observed in memory
5. Payload Storage:
   C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll
6. Execution:
   rundll32.exe launches the DLL payload
```

## Final DFIR Summary

Malware family: **Amadey Stealer**

Observed behavior:

- Masquerading process: `lssass.exe`
- Temp-based execution and staging
- External C2 communication: `41.75.84.12`
- Two downloaded modules
- DLL payload drop in `AppData\Roaming`
- DLL execution via `rundll32.exe`
- Persistence via scheduled tasks
