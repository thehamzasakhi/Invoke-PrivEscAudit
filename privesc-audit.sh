#!/usr/bin/env bash
#
# privesc-audit.sh - Linux local privilege-escalation & credential-exposure
# enumeration for AUTHORIZED penetration tests and configuration audits.
#
# Linux counterpart of Invoke-PrivEscAudit.ps1. Built in the spirit of linPEAS,
# but around the same structured findings model: every check emits a finding
# with a category, a severity (Info -> Critical), the evidence and a
# remediation note, so results export cleanly to JSON / CSV / HTML.
#
# Strictly read-only: it enumerates and reports misconfigurations. It does not
# exploit, modify or persist. The only files it writes are the report files.
#
# Use only on systems you own or are explicitly authorized to assess.
#
# Requirements: bash 4.4+, coreutils, findutils, GNU grep. Optional: getcap,
# ss/netstat, systemctl, sudo. Targets Ubuntu/Debian; degrades on other distros.
#
# Usage: ./privesc-audit.sh [-d Quick|Standard|Deep] [-f console,json,csv,html]
#                           [-m Info|Low|Medium|High|Critical] [-o DIR]
#                           [-s] [-r DIR[,DIR...]] [-x KB] [--no-sudo]
#                           [--no-color] [-v] [-h]

if [ -z "${BASH_VERSION:-}" ]; then
    echo "privesc-audit.sh must be run with bash (try: bash $0)" >&2
    exit 1
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
    echo "privesc-audit.sh requires bash 4.4 or newer (found $BASH_VERSION)" >&2
    exit 1
fi

export LC_ALL=C
ORIG_PATH=$PATH
SELF=$(readlink -f -- "$0" 2>/dev/null || printf '%s' "$0")
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"

VERSION="1.0.0"

#region ---------- Parameters ----------

DEPTH="Quick"
FORMATS="console,html"
MIN_SEV="Info"
OUTPUT_PATH="$PWD"
SECRET_SCAN=0
SCAN_ROOTS=()
MAX_KB=2048
DO_SUDO=1
COLOR="auto"
VERBOSE=0

usage() {
    cat <<'USAGE'
privesc-audit.sh - read-only Linux privilege-escalation & credential-exposure audit

Options:
  -d, --depth LEVEL          Quick (default) | Standard | Deep
                               Quick    - fast checks only
                               Standard - + pending updates, app configs, root
                                          process binaries, targeted writable sweep
                               Deep     - + full-filesystem writable sweep, full
                                          capability scan, all-FS secret scan roots
  -f, --format LIST          Comma list of: console,json,csv,html  (default: console,html)
  -m, --min-severity LEVEL   Info (default) | Low | Medium | High | Critical
  -o, --output-path DIR      Folder for report files (default: current directory)
  -s, --secret-scan          Enable the credential/secret file content scan (off by default)
  -r, --scan-roots LIST      Comma list of folders for the secret scan (implies -s)
  -x, --max-file-size-kb N   Skip files larger than N KB in the secret scan (default: 2048)
      --no-sudo              Do not run 'sudo -n -l' (it is logged in auth.log)
      --no-color             Disable ANSI colors on the console
  -v, --verbose              Print per-section timings to stderr
  -h, --help                 Show this help

Examples:
  ./privesc-audit.sh
  ./privesc-audit.sh -d Standard -s -m Medium -f console,json,csv,html
  ./privesc-audit.sh -d Deep -s
  ./privesc-audit.sh -s -r /var/www,/opt/apps -x 4096

Authorized use only.
USAGE
}

# Normalize "quick" / "QUICK" -> "Quick"
norm_word() { local v=${1,,}; printf '%s' "${v^}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--depth)            DEPTH=$(norm_word "${2:-}"); shift 2 ;;
        -f|--format)           FORMATS="${2:-}"; shift 2 ;;
        -m|--min-severity)     MIN_SEV=$(norm_word "${2:-}"); shift 2 ;;
        -o|--output-path)      OUTPUT_PATH="${2:-}"; shift 2 ;;
        -s|--secret-scan)      SECRET_SCAN=1; shift ;;
        -r|--scan-roots)       IFS=',' read -ra _roots <<< "${2:-}"; SCAN_ROOTS+=("${_roots[@]}"); SECRET_SCAN=1; shift 2 ;;
        -x|--max-file-size-kb) MAX_KB="${2:-}"; shift 2 ;;
        --no-sudo)             DO_SUDO=0; shift ;;
        --no-color)            COLOR=0; shift ;;
        -v|--verbose)          VERBOSE=1; shift ;;
        -h|--help)             usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$DEPTH" in Quick|Standard|Deep) ;; *) echo "Invalid --depth: $DEPTH" >&2; exit 2 ;; esac
case "$MIN_SEV" in Info|Low|Medium|High|Critical) ;; *) echo "Invalid --min-severity: $MIN_SEV" >&2; exit 2 ;; esac
[[ "$MAX_KB" =~ ^[0-9]+$ ]] || { echo "Invalid --max-file-size-kb: $MAX_KB" >&2; exit 2; }
FORMATS=${FORMATS,,}; FORMATS=${FORMATS// /}
IFS=',' read -ra _fmts <<< "$FORMATS"
for _f in "${_fmts[@]}"; do
    case "$_f" in console|json|csv|html) ;; *) echo "Invalid --format value: $_f" >&2; exit 2 ;; esac
done
if [[ ",$FORMATS," == *,json,* || ",$FORMATS," == *,csv,* || ",$FORMATS," == *,html,* ]]; then
    if [ ! -d "$OUTPUT_PATH" ] || [ ! -w "$OUTPUT_PATH" ]; then
        echo "Output path is not a writable directory: $OUTPUT_PATH" >&2; exit 2
    fi
fi
#endregion

#region ---------- Core model & helpers ----------

declare -A SEV_RANK=([Info]=0 [Low]=1 [Medium]=2 [High]=3 [Critical]=4)
F_CAT=(); F_TITLE=(); F_SEV=(); F_EVID=(); F_REM=(); F_TS=()

ME=$(id -un 2>/dev/null || echo "uid$EUID")
MY_UID=$EUID
MY_HOME=$(getent passwd "$MY_UID" 2>/dev/null | cut -d: -f6)
[ -n "$MY_HOME" ] || MY_HOME=${HOME:-}
HOST=$(hostname 2>/dev/null || uname -n)
IS_ROOT=0; [ "$MY_UID" -eq 0 ] && IS_ROOT=1
START_SECONDS=$SECONDS

has_format() { [[ ",$FORMATS," == *",$1,"* ]]; }

if [ "$COLOR" = "auto" ] && [ -t 1 ] && has_format console; then COLOR=1; fi
if [ "$COLOR" = "1" ]; then
    C_RESET=$'\e[0m'; C_CYAN=$'\e[36m'; C_RED=$'\e[1;31m'; C_LRED=$'\e[31m'
    C_YEL=$'\e[33m'; C_DYEL=$'\e[2;33m'; C_GRAY=$'\e[90m'; C_GREEN=$'\e[32m'
else
    C_RESET=""; C_CYAN=""; C_RED=""; C_LRED=""; C_YEL=""; C_DYEL=""; C_GRAY=""; C_GREEN=""
fi
declare -A SEV_COLOR=([Critical]="$C_RED" [High]="$C_LRED" [Medium]="$C_YEL" [Low]="$C_DYEL" [Info]="$C_GRAY")

# add_finding CATEGORY TITLE SEVERITY [EVIDENCE] [REMEDIATION]
add_finding() {
    local ts
    printf -v ts '%(%Y-%m-%dT%H:%M:%S)T' -1
    F_CAT+=("$1"); F_TITLE+=("$2"); F_SEV+=("${3:-Info}")
    F_EVID+=("${4:-}"); F_REM+=("${5:-}"); F_TS+=("$ts")
}

# ev KEY VALUE [KEY VALUE ...] -> sets $EV to "Key: value" lines
ev() {
    EV=""
    while [ $# -ge 2 ]; do EV+="$1: $2"$'\n'; shift 2; done
    EV=${EV%$'\n'}
}

section() {
    if [ "$VERBOSE" -eq 1 ]; then printf '[%4ss] %s\n' "$((SECONDS - START_SECONDS))" "$1" >&2; fi
    if has_format console; then
        local line="===== $1 "
        while [ ${#line} -lt 70 ]; do line+="="; done
        printf '\n%s%s%s\n' "$C_CYAN" "$line" "$C_RESET"
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# Mask the back half of a matched value (after truncating to 60 chars) so the
# report doesn't become a secret store itself.
mask() {
    local v=$1 cut
    [ ${#v} -gt 60 ] && v="${v:0:60}..."
    cut=$(( ${#v} / 2 ))
    local stars=""
    while [ ${#stars} -lt $(( ${#v} - cut )) ]; do stars+="*"; done
    printf '%s%s' "${v:0:cut}" "$stars"
}

# Root mode: is PATH modifiable by a non-root principal? (world/group-writable or non-root owner)
_perm_loose() {
    local info mode uid gid
    info=$(stat -L -c '%A %u %g' -- "$1" 2>/dev/null) || return 1
    read -r mode uid gid <<< "$info"
    if [ "${mode:8:1}" = "w" ]; then W_HOW="world-writable ($mode)"; return 0; fi
    if [ "${mode:5:1}" = "w" ] && [ "$gid" != "0" ]; then W_HOW="group-writable by gid $gid ($mode)"; return 0; fi
    if [ "$uid" != "0" ]; then W_HOW="owned by non-root uid $uid ($mode)"; return 0; fi
    return 1
}

# Can the relevant principal write this exact object?
#  - as a normal user: can *I* write it (access(2) semantics, honors ACLs)
#  - as root: can a *non-root* principal write it
_can_write() {
    if [ "$IS_ROOT" -eq 1 ]; then _perm_loose "$1"; return; fi
    if [ -w "$1" ]; then W_HOW="writable by $ME"; return 0; fi
    return 1
}

# Can the relevant principal replace entries inside a sticky directory?
_owns_entry() {
    if [ "$IS_ROOT" -eq 1 ]; then
        local u; u=$(stat -c '%u' -- "$1" 2>/dev/null) || return 1
        [ "$u" != "0" ]; return
    fi
    [ -O "$1" ]
}

# is_writable PATH -> 0 if PATH can be modified, replaced or created by the
# principal under test. Walks up the tree: a writable (non-sticky) ancestor
# directory lets the path be renamed away and recreated. Sets W_PATH / W_HOW.
is_writable() {
    local p=$1 cur child real
    W_PATH=""; W_HOW=""
    [[ "$p" == /* ]] || return 1
    case "$p" in /dev/*|/proc/*|/sys/*) return 1 ;; esac
    if [ -e "$p" ] && _can_write "$p"; then W_PATH=$p; return 0; fi
    cur=$p
    while [ "$cur" != "/" ]; do
        child=$cur
        cur=${cur%/*}; [ -n "$cur" ] || cur=/
        if [ -d "$cur" ] && _can_write "$cur"; then
            if [ -k "$cur" ] && [ -e "$child" ] && ! _owns_entry "$child"; then
                continue    # sticky dir (e.g. /tmp): others' entries can't be replaced
            fi
            W_PATH=$cur
            if [ -e "$p" ]; then W_HOW="replaceable: ancestor $cur is $W_HOW"
            else W_HOW="missing, creatable: ancestor $cur is $W_HOW"; fi
            return 0
        fi
    done
    # Follow a symlink once and test its target too
    if [ -L "$p" ]; then
        real=$(readlink -f -- "$p" 2>/dev/null)
        if [ -n "$real" ] && [ "$real" != "$p" ] && [ "${_IW_DEPTH:-0}" -eq 0 ]; then
            _IW_DEPTH=1 is_writable "$real" && { W_HOW="symlink target $real: $W_HOW"; return 0; }
        fi
    fi
    return 1
}

# Extract the leading executable from a command line, stripping quotes / args
# and systemd Exec prefixes (@ - : + !).
get_bin_path() {
    local cl=$1
    cl="${cl#"${cl%%[![:space:]]*}"}"
    while [[ "$cl" == [@:+!-]* ]]; do cl=${cl:1}; done
    if [[ "$cl" == \"* ]]; then cl=${cl:1}; cl=${cl%%\"*}; printf '%s' "$cl"; return; fi
    printf '%s' "${cl%%[[:space:]]*}"
}

# All absolute-path tokens in a command string (excluding output redirections).
path_tokens() {
    local s
    s=$(printf '%s' "$1" | sed -E 's/[0-9&]*>>?[[:space:]]*[^[:space:]]+//g')
    printf '%s\n' "$s" | grep -oE '(^|[[:space:]=;|&(`"'"'"'])/[^[:space:];|&<>()`"'"'"']+' |
        sed -E 's/^[^/]//' | grep -vE '^/(dev|proc|sys)(/|$)' | sort -u
}

# Is a binary name in a given associative list? Tries the raw name and
# version-stripped variants (python3.10 -> python3 -> python).
in_list() {
    local -n _list=$1
    local n=$2 a b
    a=${n%%.*}; b=${a%%[0-9]*}
    [ -n "${_list[$n]:-}" ] || [ -n "${_list[$a]:-}" ] || { [ -n "$b" ] && [ -n "${_list[$b]:-}" ]; }
}

# Read a sysctl value from /proc/sys (empty if absent)
sysctl_val() { local f="/proc/sys/${1//.//}"; [ -r "$f" ] && cat "$f" 2>/dev/null; }

# Local accounts: arrays of name/uid/home/shell for entries in /etc/passwd
U_NAME=(); U_UID=(); U_HOME=(); U_SHELL=()
while IFS=: read -r _n _p _u _g _c _h _s; do
    [ -n "$_n" ] || continue
    U_NAME+=("$_n"); U_UID+=("$_u"); U_HOME+=("$_h"); U_SHELL+=("$_s")
done < /etc/passwd 2>/dev/null

# Home dirs worth looking in: root + uid>=1000 + any account with a login shell
HOME_DIRS=(); HOME_OWNER=()
declare -A _seen_home=()
for i in "${!U_NAME[@]}"; do
    h=${U_HOME[$i]}; u=${U_UID[$i]}; s=${U_SHELL[$i]}
    [ -n "$h" ] && [ "$h" != "/" ] && [ -d "$h" ] || continue
    if [ "$u" = "0" ] || { [ "$u" -ge 1000 ] 2>/dev/null && [ "$u" != "65534" ]; } || [[ "$s" != *nologin && "$s" != */false && -n "$s" ]]; then
        [ -n "${_seen_home[$h]:-}" ] && continue
        _seen_home[$h]=1; HOME_DIRS+=("$h"); HOME_OWNER+=("${U_NAME[$i]}")
    fi
done
for h in /home/*; do
    [ -d "$h" ] && [ -z "${_seen_home[$h]:-}" ] && { _seen_home[$h]=1; HOME_DIRS+=("$h"); HOME_OWNER+=("${h##*/}"); }
done
unset _seen_home

# GTFOBins-style binaries that give a shell / file read-write when SUID or via sudo
declare -A GTFO_SUID=()
for _b in aria2c arp ash awk base32 base64 basenc bash bc busybox capsh cat chmod chown chroot \
          cp csh curl cut dash date dd dialog diff dmsetup docker ed emacs env eqn expand expect \
          file find flock fmt fold gawk gdb gimp grep gtester hd head hexdump highlight iconv \
          install ionice ip jjs join jq jrunscript ksh less logsave look lua make mawk more mv \
          nano nawk nice nl nmap node nohup od openssl paste perl pg php pico python readelf \
          restic rev rlwrap rsync ruby run-parts rview rvim sed setarch sh shuf soelim sort \
          sqlite3 ss start-stop-daemon stdbuf strace strings sysctl systemctl tac tail taskset \
          tbl tclsh tee tftp time timeout troff ul unexpand uniq unshare update-alternatives \
          uudecode uuencode view vim vimdiff watch wget xargs xxd xz zip zsh zsoelim; do
    GTFO_SUID[$_b]=1
done
declare -A GTFO_SUDO=()
for _b in "${!GTFO_SUID[@]}" apache2 apt apt-get ash at bundle cpan crontab dpkg dnf docker \
          ftp gcc gem git iftop journalctl less lftp ltrace man mount mysql neofetch nsenter \
          pip pip3 pkexec psql puppet rpm screen scp service sftp smbclient snap socat ssh \
          sudo su tar tcpdump tmux vi yum zypper; do
    GTFO_SUDO[$_b]=1
done
# SUID/SGID binaries expected on a stock Ubuntu/Debian install
declare -A STD_SETID=()
for _b in at bsd-write chage chfn chrome-sandbox chsh crontab dbus-daemon-launch-helper \
          dotlockfile expiry fusermount fusermount3 gpasswd ksu lxc-user-nic mail-lock \
          mail-touchlock mail-unlock mlocate mount mount.cifs mount.nfs mount.nfs4 newgidmap \
          newgrp newuidmap ntfs-3g pam_extrausers_chkpwd passwd ping ping6 pkexec plocate \
          polkit-agent-helper-1 pppd sg snap-confine ssh-agent ssh-keysign staprun su sudo \
          sudoedit traceroute6.iputils umount unix_chkpwd userhelper utempter \
          vmware-user-suid-wrapper wall write Xorg Xorg.wrap; do
    STD_SETID[$_b]=1
done
unset _b
#endregion

#region ---------- System & patch context ----------
check_system() {
    section "SYSTEM CONTEXT"
    local os="unknown" kernel arch virt container="no" up boot

    if [ -r /etc/os-release ]; then
        os=$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-$NAME $VERSION}" )
    fi
    kernel=$(uname -r); arch=$(uname -m)
    virt=$(systemd-detect-virt 2>/dev/null); [ -n "$virt" ] || virt="unknown"
    detect_container && container="yes ($CONTAINER_KIND)"
    up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
    boot=$(date -d "@$(( $(date +%s) - ${up:-0} ))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)

    ev Host "$HOST" OS "$os" Kernel "$kernel" Arch "$arch" Virtualization "$virt" \
       Container "$container" LastBoot "${boot:-unknown}" CurrentUser "$ME (uid=$MY_UID)" \
       Id "$(id 2>/dev/null)" Bash "$BASH_VERSION" Depth "$DEPTH"
    add_finding 'System' 'Host / OS context' Info "$EV"
    has_format console && printf '%s\n' "$EV" | sed 's/^/  /'

    if [ "$IS_ROOT" -eq 1 ]; then
        add_finding 'System' 'Running as root: writability checks report non-root-modifiable paths' Info \
            "Each 'writable' finding means a non-root principal (world/group/owner) can modify the path." \
            'For an attacker-eye view of privesc paths, also run as the low-privileged account under test.'
    fi

    # Package-change recency - stale patching is a soft privesc signal
    local stamp="" src=""
    if [ -f /var/lib/dpkg/status ]; then stamp=$(stat -c %Y /var/lib/dpkg/status 2>/dev/null); src="/var/lib/dpkg/status mtime"
    elif have rpm; then stamp=$(rpm -qa --qf '%{INSTALLTIME}\n' 2>/dev/null | sort -n | tail -1); src="rpm INSTALLTIME"
    fi
    if [ -n "$stamp" ]; then
        local age=$(( ( $(date +%s) - stamp ) / 86400 )) sev=Info
        [ "$age" -gt 60 ] && sev=Low
        [ "$age" -gt 120 ] && sev=Medium
        ev LastPackageChange "$(date -d "@$stamp" '+%Y-%m-%d' 2>/dev/null)" Source "$src"
        add_finding 'System' "Most recent package change is $age days old" "$sev" "$EV" \
            'Confirm patch cadence; stale patching widens the kernel/privesc exploit window.'
    fi

    # Reboot pending / running kernel older than installed kernel
    local newest=""
    newest=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's#^/boot/vmlinuz-##' | sort -V | tail -1)
    if [ -e /var/run/reboot-required ] || { [ -n "$newest" ] && [ "$newest" != "$kernel" ]; }; then
        ev RunningKernel "$kernel" NewestInstalled "${newest:-n/a}" \
           RebootRequired "$([ -e /var/run/reboot-required ] && echo yes || echo no)" \
           Packages "$(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null)"
        add_finding 'System' 'Reboot pending: running kernel/libraries may predate installed patches' Low "$EV" \
            'Installed security updates are not active until reboot. Schedule one.'
    fi

    # Pending updates (Standard+: apt-check / apt simulation takes a few seconds)
    if [ "$DEPTH" != "Quick" ]; then
        local out total sec
        if [ -x /usr/lib/update-notifier/apt-check ]; then
            out=$(/usr/lib/update-notifier/apt-check 2>&1 >/dev/null | tail -1)
            total=${out%%;*}; sec=${out##*;}
        elif have apt-get; then
            out=$(apt-get -s -q dist-upgrade 2>/dev/null | grep '^Inst ')
            total=$(printf '%s' "$out" | grep -c '^Inst ')
            sec=$(printf '%s' "$out" | grep -ci 'security')
        fi
        if [[ "${total:-}" =~ ^[0-9]+$ ]] && [[ "${sec:-}" =~ ^[0-9]+$ ]]; then
            local sev=Info; [ "$total" -gt 0 ] && sev=Low; [ "$sec" -gt 0 ] && sev=Medium
            ev PendingUpdates "$total" PendingSecurityUpdates "$sec"
            add_finding 'System' "$total pending package updates ($sec security)" "$sev" "$EV" \
                'Apply outstanding security updates (apt upgrade / unattended-upgrades).'
        fi
    fi
}

CONTAINER_KIND=""
detect_container() {
    CONTAINER_KIND=""
    if [ -f /.dockerenv ]; then CONTAINER_KIND="docker"
    elif [ -f /run/.containerenv ]; then CONTAINER_KIND="podman"
    elif [ -n "${KUBERNETES_SERVICE_HOST:-}" ]; then CONTAINER_KIND="kubernetes"
    elif grep -qaE 'docker|kubepods|containerd|lxc|libpod' /proc/1/cgroup 2>/dev/null; then
        CONTAINER_KIND=$(grep -oaE 'docker|kubepods|containerd|lxc|libpod' /proc/1/cgroup | head -1)
    elif [ -r /proc/1/environ ] && tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -q '^container='; then
        CONTAINER_KIND=$(tr '\0' '\n' < /proc/1/environ | sed -n 's/^container=//p' | head -1)
    fi
    [ -n "$CONTAINER_KIND" ]
}
#endregion

#region ---------- Users, groups & account database ----------
check_users() {
    section "USERS & GROUPS"
    local groups g
    groups=$(id -Gn 2>/dev/null)
    ev User "$ME" Uid "$MY_UID" Groups "$groups" Root "$([ $IS_ROOT -eq 1 ] && echo yes || echo no)"
    add_finding 'User' "Running as root: $([ $IS_ROOT -eq 1 ] && echo true || echo false)" Info "$EV"

    # Groups that are root-equivalent or expose sensitive data
    declare -A dg=(
        [docker]="High|Mount the host / into a container (docker run -v /:/mnt) -> root."
        [lxd]="High|Create a privileged container with host / mounted -> root."
        [lxc]="High|Create a privileged container with host / mounted -> root."
        [incus-admin]="High|Create a privileged container with host / mounted -> root."
        [libvirt]="High|Define a VM/pool with host disks attached -> root."
        [microk8s]="High|Cluster-admin on the local Kubernetes -> privileged pod -> root."
        [disk]="High|Raw block-device access (debugfs) -> read /etc/shadow, write any file."
        [shadow]="High|Read /etc/shadow password hashes for offline cracking."
        [root]="Medium|gid 0: read/write any group-root files."
        [sudo]="Medium|sudo group: root with this account's password."
        [admin]="Medium|admin group: root with this account's password (older Ubuntu)."
        [wheel]="Medium|wheel group: root with this account's password."
        [adm]="Low|Read /var/log - logs often contain credentials and tokens."
        [systemd-journal]="Low|Read the full system journal (credentials in logs)."
        [video]="Low|Framebuffer access (screen capture of logged-in sessions)."
        [kvm]="Low|Direct /dev/kvm access."
    )
    for g in $groups; do
        [ "$IS_ROOT" -eq 1 ] && break
        if [ -n "${dg[$g]:-}" ]; then
            ev Group "$g" User "$ME"
            add_finding 'User' "Member of privileged group '$g'" "${dg[$g]%%|*}" "$EV" \
                "Abuse path: ${dg[$g]#*|} Remove membership unless required."
        fi
    done

    # Membership of the same groups across all local accounts (inventory)
    local inv="" grp members
    for grp in sudo admin wheel docker lxd libvirt disk shadow adm; do
        members=$(getent group "$grp" 2>/dev/null | cut -d: -f4)
        [ -n "$members" ] && inv+="$grp: $members"$'\n'
    done
    [ -n "$inv" ] && add_finding 'User' 'Privileged group membership (all accounts)' Info "${inv%$'\n'}"

    # Login-capable accounts
    local logins="" i
    for i in "${!U_NAME[@]}"; do
        case "${U_SHELL[$i]}" in *nologin|*/false|*/sync|"") ;; *) logins+="${U_NAME[$i]} (uid ${U_UID[$i]}, ${U_SHELL[$i]})"$'\n' ;; esac
    done
    [ -n "$logins" ] && add_finding 'User' 'Accounts with a login shell' Info "${logins%$'\n'}"

    # UID 0 accounts other than root
    for i in "${!U_NAME[@]}"; do
        if [ "${U_UID[$i]}" = "0" ] && [ "${U_NAME[$i]}" != "root" ]; then
            ev Account "${U_NAME[$i]}" Uid 0 Shell "${U_SHELL[$i]}"
            add_finding 'User' "Non-root account with UID 0: ${U_NAME[$i]}" High "$EV" \
                'A second UID-0 account is a classic backdoor. Verify and remove.'
        fi
    done

    # Password hashes / empty passwords directly in /etc/passwd
    local name pw
    while IFS=: read -r name pw _; do
        [ -n "$name" ] || continue
        if [ -z "$pw" ]; then
            add_finding 'User' "Empty password field in /etc/passwd: $name" Critical "Account: $name" \
                'Account may allow passwordless login / su. Set "x" and a shadow password.'
        elif [ "$pw" != "x" ] && [ "$pw" != "*" ] && [[ "$pw" != !* ]]; then
            ev Account "$name" HashPrefix "${pw:0:3}..."
            add_finding 'User' "Password hash stored in world-readable /etc/passwd: $name" Critical "$EV" \
                'Hashes in /etc/passwd are readable by everyone. Run pwconv / move to /etc/shadow.'
        fi
    done < /etc/passwd 2>/dev/null

    # Readable home directories of other accounts
    local readable=""
    for i in "${!HOME_DIRS[@]}"; do
        h=${HOME_DIRS[$i]}
        [ "$h" = "$MY_HOME" ] && continue
        [ "$IS_ROOT" -eq 1 ] && continue
        if [ -r "$h" ] && [ -x "$h" ]; then readable+="$h (${HOME_OWNER[$i]})"$'\n'; fi
    done
    if [ -n "$readable" ]; then
        local sev=Low; [[ "$readable" == *"/root ("* ]] && sev=High
        add_finding 'User' 'Other users'"'"' home directories are listable' "$sev" "${readable%$'\n'}" \
            'Home dirs should be 0750/0700. Readable homes leak keys, histories and configs.'
    fi
}
#endregion

#region ---------- Sudo ----------
check_sudo() {
    section "SUDO"
    if ! have sudo; then add_finding 'Sudo' 'sudo not installed' Info; return; fi
    add_finding 'Sudo' 'sudo version' Info "$(sudo -V 2>/dev/null | head -1)" \
        'Compare against vendor advisories (e.g. Baron Samedit CVE-2021-3156); distros backport fixes.'

    # sudoers files: writable = instant root; readable by non-root = rule disclosure
    local f
    for f in /etc/sudoers /etc/sudoers.d /etc/sudoers.d/* /etc/sudo.conf; do
        [ -e "$f" ] || continue
        if is_writable "$f"; then
            ev Path "$f" How "$W_HOW"
            add_finding 'Sudo' "Writable sudo configuration: $f" Critical "$EV" \
                'Anyone who can write sudoers / sudo.conf can grant themselves root. Fix ownership (root:root 0440/0750).'
        elif [ "$IS_ROOT" -eq 0 ] && [ -f "$f" ] && [ -r "$f" ] && [ "$f" != /etc/sudo.conf ]; then
            add_finding 'Sudo' "sudoers file readable by $ME: $f" Low "Path: $f" \
                'sudoers should be 0440 root:root; readable rules help attackers target NOPASSWD entries.'
        fi
    done

    # NOPASSWD rules visible in readable sudoers (root run / misconfigured perms)
    local rules
    rules=$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | grep -E 'NOPASSWD|!authenticate')
    if [ -n "$rules" ]; then
        add_finding 'Sudo' 'NOPASSWD rules present in sudoers' Medium "$rules" \
            'Each NOPASSWD command is a privesc candidate if it allows shell escapes, arguments or writable paths.'
    fi

    [ "$IS_ROOT" -eq 1 ] && return
    if [ "$DO_SUDO" -eq 0 ]; then add_finding 'Sudo' "sudo -l skipped (--no-sudo)" Info; return; fi

    # Non-interactive: never prompts for a password
    local out
    out=$(sudo -n -l 2>&1 </dev/null)
    if printf '%s' "$out" | grep -qiE 'password is required|a terminal is required'; then
        add_finding 'Sudo' 'sudo -l requires a password (no NOPASSWD rules)' Info "$out" \
            'If you know the account password, run "sudo -l" interactively to list rules.'
        return
    fi
    if printf '%s' "$out" | grep -qiE 'may not run sudo|not in the sudoers|unknown user'; then
        add_finding 'Sudo' "$ME may not run sudo" Info "$out"
        return
    fi
    if ! printf '%s' "$out" | grep -qi 'may run the following'; then
        add_finding 'Sudo' 'sudo -l returned unexpected output' Info "$out"
        return
    fi
    add_finding 'Sudo' "sudo rules for $ME" Info "$out"

    # Defaults that enable environment injection
    if printf '%s' "$out" | grep -qE 'env_keep[^,]*(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|BASH_ENV)'; then
        add_finding 'Sudo' 'sudo preserves a loader/interpreter env var (env_keep)' High \
            "$(printf '%s' "$out" | grep -oE 'env_keep[^,]*')" \
            'LD_PRELOAD/LD_LIBRARY_PATH/PYTHONPATH kept across sudo -> code execution as root. Remove from env_keep.'
    fi
    if printf '%s' "$out" | grep -qE '!env_reset'; then
        add_finding 'Sudo' 'sudo env_reset disabled (!env_reset)' High "!env_reset" \
            'Caller environment reaches root commands. Re-enable env_reset.'
    fi
    # secure_path entries writable
    local sp d
    sp=$(printf '%s' "$out" | grep -oE 'secure_path=[^,[:space:]]+' | head -1 | cut -d= -f2)
    if [ -n "$sp" ]; then
        IFS=: read -ra _sp <<< "$sp"
        for d in "${_sp[@]}"; do
            if is_writable "$d"; then
                ev SecurePathDir "$d" How "$W_HOW"
                add_finding 'Sudo' "Writable directory in sudo secure_path: $d" High "$EV" \
                    'Commands run via sudo by name resolve here first -> binary planting as root. Fix permissions.'
            fi
        done
    fi

    # Per-rule analysis: lines after "may run the following commands"
    local line runas tags cmds cmd bin base
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]+\( ]] || continue
        runas=$(printf '%s' "$line" | sed -nE 's/^[[:space:]]*\(([^)]*)\).*/\1/p')
        tags=$(printf '%s' "$line" | sed -nE 's/^[[:space:]]*\([^)]*\)[[:space:]]*(([A-Z_]+:[[:space:]]*)*).*/\1/p')
        cmds=$(printf '%s' "$line" | sed -E 's/^[[:space:]]*\([^)]*\)[[:space:]]*([A-Z_]+:[[:space:]]*)*//')
        local nopw=0; [[ "$tags" == *NOPASSWD* ]] && nopw=1
        IFS=',' read -ra _cmds <<< "$cmds"
        for cmd in "${_cmds[@]}"; do
            cmd="${cmd#"${cmd%%[![:space:]]*}"}"
            [ -n "$cmd" ] || continue
            ev Rule "$line" RunAs "$runas" Command "$cmd"
            if [ "$cmd" = "ALL" ]; then
                if [ $nopw -eq 1 ]; then
                    add_finding 'Sudo' "sudo NOPASSWD: ALL as ($runas)" Critical "$EV" \
                        'Passwordless root for this account. Restrict to specific commands.'
                else
                    add_finding 'Sudo' "sudo ALL as ($runas) with password" Medium "$EV" \
                        "Full root with $ME's password; account compromise == root."
                fi
                continue
            fi
            bin=$(get_bin_path "$cmd"); base=${bin##*/}
            if is_writable "$bin"; then
                add_finding 'Sudo' "sudo command binary is writable: $bin" Critical "$EV"$'\n'"How: $W_HOW" \
                    'Replace the binary -> runs as the sudo target. Fix ownership/permissions.'
            elif in_list GTFO_SUDO "$base"; then
                add_finding 'Sudo' "sudo$([ $nopw -eq 1 ] && echo ' NOPASSWD') GTFOBins-style binary: $base" \
                    "$([ $nopw -eq 1 ] && echo High || echo Medium)" "$EV" \
                    "$base can spawn a shell or read/write files as ($runas). See gtfobins.github.io/gtfobins/$base/."
            elif [[ "$cmd" == *\** ]]; then
                add_finding 'Sudo' "sudo rule with wildcard arguments: $cmd" Medium "$EV" \
                    'Wildcards in sudo rules usually allow argument/path injection. Pin exact arguments.'
            elif [ $nopw -eq 1 ]; then
                add_finding 'Sudo' "sudo NOPASSWD command: $cmd" Medium "$EV" \
                    'Review for shell escapes, writable scripts it calls, relative paths and env handling.'
            fi
            if [[ "$tags" == *SETENV* ]]; then
                add_finding 'Sudo' "sudo SETENV tag on: $cmd" High "$EV" \
                    'SETENV lets the caller set LD_PRELOAD/PYTHONPATH/BASH_ENV for the command. Remove SETENV.'
            fi
        done
    done <<< "$out"
}
#endregion

#region ---------- SUID / SGID ----------
check_suid() {
    section "SUID / SGID BINARIES"
    local prune=( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/lib/docker
                  -o -path /var/lib/containerd -o -fstype nfs -o -fstype nfs4 -o -fstype cifs
                  -o -fstype smb3 -o -fstype fuse.sshfs )
    [ "$DEPTH" != "Deep" ] && prune+=( -o -path /snap )
    local files=() f
    mapfile -d '' files < <(find / \( "${prune[@]}" \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)

    local inventory="" info mode owner group base
    for f in "${files[@]}"; do
        info=$(stat -c '%A %U %G' -- "$f" 2>/dev/null) || continue
        read -r mode owner group <<< "$info"
        inventory+="$mode $owner:$group $f"$'\n'
        base=${f##*/}
        local suid=0; [[ "${mode:3:1}" == [sS] ]] && suid=1
        local kind; kind=$([ $suid -eq 1 ] && echo SUID || echo SGID)
        local who; who=$([ $suid -eq 1 ] && echo "$owner" || echo "group $group")

        if is_writable "$f"; then
            ev Path "$f" Mode "$mode" Owner "$owner:$group" How "$W_HOW"
            add_finding 'SUID' "Writable $kind binary: $f" Critical "$EV" \
                "Overwrite the binary -> code execution as $who. Fix ownership/permissions."
            continue
        fi
        ev Path "$f" Mode "$mode" Owner "$owner:$group"
        if in_list GTFO_SUID "$base"; then
            if [ $suid -eq 1 ]; then
                add_finding 'SUID' "SUID GTFOBins-style binary: $f" "$([ "$owner" = root ] && echo High || echo Medium)" "$EV" \
                    "$base runs as $owner and can spawn a shell / read-write files. See gtfobins.github.io/gtfobins/$base/. Remove the SUID bit."
            else
                add_finding 'SUID' "SGID GTFOBins-style binary: $f" Medium "$EV" \
                    "$base runs with group $group. Remove the SGID bit unless required."
            fi
        elif ! in_list STD_SETID "$base"; then
            local sev=Low
            case "$f" in /home/*|/tmp/*|/var/tmp/*|/dev/shm/*|/opt/*|/usr/local/*|/srv/*|/var/www/*) sev=Medium ;; esac
            [ $suid -eq 0 ] && sev=Info
            add_finding 'SUID' "Non-standard $kind binary: $f" "$sev" "$EV" \
                'Custom setuid code: review for command injection, relative exec, PATH / library hijack.'
        fi
    done
    [ -n "$inventory" ] && add_finding 'SUID' "SUID/SGID inventory (${#files[@]} files)" Info "${inventory%$'\n'}"
}
#endregion

#region ---------- File & process capabilities ----------
check_capabilities() {
    section "CAPABILITIES"
    local danger='cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_chown|cap_fowner|cap_setfcap|cap_sys_rawio|cap_bpf|cap_sys_chroot|cap_perfmon'
    if have getcap; then
        local roots=()
        if [ "$DEPTH" = "Deep" ]; then
            local d; for d in /*; do case "$d" in /proc|/sys|/dev|/run) ;; *) [ -d "$d" ] && roots+=("$d") ;; esac; done
        else
            roots=(/usr /bin /sbin /lib /lib64 /opt /home /srv /var /tmp /etc /root)
        fi
        local existing=() r; for r in "${roots[@]}"; do [ -d "$r" ] && [ ! -L "$r" ] && existing+=("$r"); done
        local line path caps base inv=""
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            path=${line%% *}; caps=${line#* }; base=${path##*/}
            inv+="$line"$'\n'
            ev Path "$path" Capabilities "$caps"
            if is_writable "$path"; then
                add_finding 'Capabilities' "Writable binary with file capabilities: $path" Critical "$EV"$'\n'"How: $W_HOW" \
                    'Replace the binary to inherit its capabilities. Fix permissions.'
            elif printf '%s' "$caps" | grep -qiE "$danger"; then
                local sev=High
                if printf '%s' "$caps" | grep -qiE 'cap_setuid|cap_sys_admin' && in_list GTFO_SUID "$base"; then sev=Critical; fi
                add_finding 'Capabilities' "Dangerous capability on $path" "$sev" "$EV" \
                    "Capabilities like setuid/dac_*/sys_admin/sys_ptrace are root-equivalent on interpreters & editors. Remove with setcap -r unless required."
            elif printf '%s' "$caps" | grep -qiE 'cap_net_admin|cap_net_raw'; then
                case "$base" in ping|ping6|mtr-packet|gst-ptp-helper|arping|fping|clockdiff) ;; *)
                    add_finding 'Capabilities' "Network capability on $path" Low "$EV" \
                        'cap_net_raw/net_admin allow sniffing/spoofing and network reconfiguration. Verify need.' ;;
                esac
            fi
        done < <(getcap -r "${existing[@]}" 2>/dev/null | sed -E 's/[[:space:]]+=[[:space:]]+/ /; s/[[:space:]]+/ /')
        [ -n "$inv" ] && add_finding 'Capabilities' 'File capability inventory' Info "${inv%$'\n'}"
    else
        add_finding 'Capabilities' 'getcap not available; file capability scan skipped' Info '' \
            'Install libcap2-bin (getcap) for capability enumeration.'
    fi

    # Capabilities of the current process
    local eff bnd amb
    eff=$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null)
    bnd=$(awk '/^CapBnd:/{print $2}' /proc/self/status 2>/dev/null)
    amb=$(awk '/^CapAmb:/{print $2}' /proc/self/status 2>/dev/null)
    if [ -n "$eff" ]; then
        local dec=""; have capsh && dec=$(capsh --decode="$eff" 2>/dev/null | cut -d= -f2)
        ev CapEff "$eff" Decoded "${dec:-n/a}" CapBnd "$bnd" CapAmb "$amb"
        if [ "$IS_ROOT" -eq 0 ] && [[ ! "$eff" =~ ^0+$ ]]; then
            add_finding 'Capabilities' 'Current process holds effective capabilities as non-root' High "$EV" \
                'Non-root shell with capabilities - check each for a direct root path.'
        else
            add_finding 'Capabilities' 'Current process capabilities' Info "$EV"
        fi
    fi
}
#endregion

#region ---------- Services (systemd / SysV) ----------
check_services() {
    section "SERVICES"
    local unit_dirs=(/etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system
                     /usr/local/lib/systemd/system /etc/systemd/system.control)
    local d real
    declare -A seen_dir=() seen_unit=()

    for d in "${unit_dirs[@]}"; do
        [ -d "$d" ] || continue
        real=$(readlink -f -- "$d"); [ -n "${seen_dir[$real]:-}" ] && continue; seen_dir[$real]=1
        if is_writable "$d"; then
            ev Directory "$d" How "$W_HOW"
            add_finding 'Service' "Writable systemd unit directory: $d" High "$EV" \
                'Can create/override units that run as root (on reboot or daemon-reload). Fix permissions.'
        fi
    done

    local u count=0
    while IFS= read -r -d '' u; do
        real=$(readlink -f -- "$u"); [ -n "$real" ] || continue
        [ "$real" = "/dev/null" ] && continue          # masked
        [ -n "${seen_unit[$real]:-}" ] && continue; seen_unit[$real]=1
        count=$((count + 1))
        local name=${u##*/}
        local svc_user; svc_user=$(grep -m1 -E '^[[:space:]]*User=' "$real" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')
        local runas=${svc_user:-root}
        local sev_hi=High sev_mid=Medium
        [ "$runas" != "root" ] && [ "$runas" != "0" ] && { sev_hi=Medium; sev_mid=Low; }

        if is_writable "$real"; then
            ev Unit "$u" File "$real" RunAs "$runas" How "$W_HOW"
            add_finding 'Service' "Writable systemd unit: $name" "$sev_hi" "$EV" \
                "Edit ExecStart -> code execution as $runas on next (re)start. Fix ownership/permissions."
            continue
        fi

        # Exec*= commands: the binary and any script/path arguments
        local line cmd bin tok
        while IFS= read -r line; do
            cmd=${line#*=}
            bin=$(get_bin_path "$cmd")
            if [[ "$bin" == /* ]] && is_writable "$bin"; then
                ev Unit "$name" Line "$line" Binary "$bin" RunAs "$runas" How "$W_HOW"
                add_finding 'Service' "Writable service binary: $name" "$sev_hi" "$EV" \
                    "Replaceable service image -> code execution as $runas. Fix ACLs on the binary/folder."
            fi
            while IFS= read -r tok; do
                [ -n "$tok" ] && [ "$tok" != "$bin" ] || continue
                [ -d "$tok" ] && continue
                if is_writable "$tok"; then
                    local sev=$sev_mid
                    [[ "$tok" =~ \.(sh|bash|py|pl|rb|php|js|lua|jar)$ ]] || [ -x "$tok" ] && sev=$sev_hi
                    ev Unit "$name" Line "$line" Path "$tok" RunAs "$runas" How "$W_HOW"
                    add_finding 'Service' "Writable path referenced by service: $name -> $tok" "$sev" "$EV" \
                        'Scripts/configs consumed by a privileged service must not be user-modifiable.'
                fi
            done < <(path_tokens "${cmd#*[[:space:]]}")
        done < <(grep -hE '^[[:space:]]*Exec(Start|StartPre|StartPost|Reload|Stop|StopPost|Condition)=' "$real" 2>/dev/null)

        # EnvironmentFile= (LD_PRELOAD injection)
        local envf
        while IFS= read -r envf; do
            envf=${envf#*=}; envf=${envf#-}
            if [[ "$envf" == /* ]] && is_writable "$envf"; then
                ev Unit "$name" EnvironmentFile "$envf" RunAs "$runas" How "$W_HOW"
                add_finding 'Service' "Writable EnvironmentFile for $name" "$sev_hi" "$EV" \
                    "Inject LD_PRELOAD / PATH into a service running as $runas. Fix permissions."
            fi
        done < <(grep -hE '^[[:space:]]*EnvironmentFile=' "$real" 2>/dev/null)
    done < <(find "${unit_dirs[@]}" -maxdepth 2 \( -name '*.service' -o -name '*.socket' -o -name '*.timer' -o -name '*.path' -o -path '*.d/*.conf' \) -print0 2>/dev/null)
    add_finding 'Service' "systemd units scanned: $count" Info

    # Manager PATH: relative Exec names resolve here
    if have systemctl; then
        local mpath
        mpath=$(systemctl show-environment 2>/dev/null | sed -n 's/^PATH=//p')
        if [ -n "$mpath" ]; then
            IFS=: read -ra _mp <<< "$mpath"
            for d in "${_mp[@]}"; do
                if is_writable "$d"; then
                    ev Directory "$d" ManagerPATH "$mpath" How "$W_HOW"
                    add_finding 'Service' "Writable directory in systemd manager PATH: $d" High "$EV" \
                        'Units with relative Exec names resolve here -> binary planting as root.'
                fi
            done
        fi
        if [ "$DEPTH" != "Quick" ]; then
            local timers; timers=$(systemctl list-timers --all --no-pager --no-legend 2>/dev/null)
            [ -n "$timers" ] && add_finding 'Service' 'systemd timers' Info "$timers"
        fi
    fi

    # SysV init scripts and rc.local
    local f
    for f in /etc/init.d/* /etc/rc.local /etc/rc.d/rc.local; do
        [ -f "$f" ] || continue
        if is_writable "$f"; then
            ev Path "$f" How "$W_HOW"
            add_finding 'Service' "Writable init script: $f" High "$EV" \
                'Init scripts run as root at boot / service start. Fix ownership/permissions.'
        fi
    done
}
#endregion

#region ---------- Cron ----------
check_cron() {
    section "CRON / SCHEDULED JOBS"
    local f d
    # Writable crontab files & directories
    for f in /etc/crontab /etc/anacrontab /etc/cron.d /etc/cron.d/* /var/spool/cron /var/spool/cron/crontabs; do
        [ -e "$f" ] || continue
        if is_writable "$f"; then
            ev Path "$f" How "$W_HOW"
            add_finding 'Cron' "Writable cron configuration: $f" Critical "$EV" \
                'Add a job that runs as root. Fix ownership/permissions (root:root, 0644 / 0755).'
        fi
    done
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly; do
        [ -d "$d" ] || continue
        if is_writable "$d"; then
            ev Directory "$d" How "$W_HOW"
            add_finding 'Cron' "Writable run-parts directory: $d" High "$EV" \
                'Drop a script that run-parts executes as root. Fix permissions.'
        fi
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            if is_writable "$f"; then
                ev Script "$f" RunAs root How "$W_HOW"
                add_finding 'Cron' "Writable cron script: $f" High "$EV" \
                    'Replaceable script runs as root on schedule. Fix permissions.'
            fi
        done
    done

    # Parse system crontabs (with user field) and readable user crontabs
    local jobs="" file
    local -a cfiles=(/etc/crontab /etc/cron.d/*)
    local -a ufiles=(/var/spool/cron/crontabs/* /var/spool/cron/*)
    for file in "${cfiles[@]}" "${ufiles[@]}"; do
        [ -f "$file" ] && [ -r "$file" ] || continue
        local has_user=1; [[ "$file" == /var/spool/* ]] && has_user=0
        local cpath="" line
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
            if [[ "$line" =~ ^[[:space:]]*PATH[[:space:]]*=[[:space:]]*(.*)$ ]]; then
                cpath=${BASH_REMATCH[1]//\"/}
                IFS=: read -ra _cp <<< "$cpath"
                for d in "${_cp[@]}"; do
                    if is_writable "$d"; then
                        ev File "$file" PATH "$cpath" Directory "$d" How "$W_HOW"
                        add_finding 'Cron' "Writable directory in crontab PATH: $d" High "$EV" \
                            'Jobs calling commands by name resolve here first -> binary planting. Fix permissions.'
                    fi
                done
                continue
            fi
            [[ "$line" =~ ^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*= ]] && continue
            local -a fl; read -ra fl <<< "$line"
            local skip user cmd
            if [[ "${fl[0]}" == @* ]]; then skip=1; else skip=5; fi
            if [ $has_user -eq 1 ]; then user=${fl[$skip]}; skip=$((skip + 1)); else user=${file##*/}; fi
            cmd="${fl[*]:$skip}"
            [ -n "$cmd" ] || continue
            jobs+="[$file] ($user) $cmd"$'\n'
            local sev=High; [ "$user" != "root" ] && sev=Medium
            [ "$IS_ROOT" -eq 0 ] && [ "$user" = "$ME" ] && continue

            local tok bin
            bin=$(get_bin_path "$cmd")
            while IFS= read -r tok; do
                [ -n "$tok" ] || continue
                [ -d "$tok" ] && continue
                if is_writable "$tok"; then
                    ev File "$file" Job "$cmd" RunAs "$user" Path "$tok" How "$W_HOW"
                    if [ "$tok" = "$bin" ] || [[ "$tok" =~ \.(sh|bash|py|pl|rb|php|js|lua|jar)$ ]] || { [ -f "$tok" ] && [ -x "$tok" ]; }; then
                        add_finding 'Cron' "Writable script/binary in $user cron job: $tok" "$sev" "$EV" \
                            "Script/binary executed by cron as $user is modifiable. Fix permissions."
                    else
                        add_finding 'Cron' "Writable data path used by $user cron job: $tok" Low "$EV" \
                            "Not executed directly, but a $user job reads/writes it (symlink or data tampering). Keep job paths root-owned."
                    fi
                fi
            done < <(path_tokens "$cmd")
            if [[ "$bin" != /* ]] && [ -n "$cpath" ]; then
                IFS=: read -ra _cp <<< "$cpath"
                for d in "${_cp[@]}"; do
                    [ -e "$d/$bin" ] && break
                    if is_writable "$d/$bin"; then
                        ev File "$file" Job "$cmd" RunAs "$user" PlantPath "$d/$bin" How "$W_HOW"
                        add_finding 'Cron' "Relative command '$bin' in $user cron job is hijackable" "$sev" "$EV" \
                            'Use absolute paths in cron jobs and keep PATH directories root-owned.'
                        break
                    fi
                done
            fi
            local wc_rx='(tar|chown|chmod|rsync|7z|zip)[^|;]*[[:space:]/]\*([[:space:]]|$)'
            if [[ "$cmd" =~ $wc_rx ]]; then
                ev File "$file" Job "$cmd" RunAs "$user"
                add_finding 'Cron' "Wildcard argument in $user cron job (wildcard injection candidate)" Medium "$EV" \
                    'If the wildcard directory is writable, crafted filenames become options (e.g. tar --checkpoint-action). Use -- and explicit paths.'
            fi
        done < "$file"
    done
    [ -n "$jobs" ] && add_finding 'Cron' 'Scheduled cron jobs' Info "${jobs%$'\n'}"
    if [ "$IS_ROOT" -eq 0 ] && ls /var/spool/cron/crontabs/* >/dev/null 2>&1; then
        add_finding 'Cron' 'Other users'"'"' crontabs are readable' Low "$(ls -l /var/spool/cron/crontabs/ 2>/dev/null)" \
            '/var/spool/cron/crontabs should be 1730 root:crontab with 0600 files.'
    fi
}
#endregion

#region ---------- Login hooks, autoruns & loader config ----------
check_autoruns() {
    section "AUTORUNS / LOGIN HOOKS / LOADER"
    # severity|reason|glob...
    local specs=(
        "Critical|Loaded into every process (including SUID) -> root|/etc/ld.so.preload"
        "Critical|PAM modules/config run during every authentication -> root|/etc/pam.d /etc/pam.d/* /etc/security/pam_env.conf"
        "Critical|Account database|/etc/passwd /etc/group /etc/shadow /etc/gshadow"
        "High|Library search path for root/SUID processes (after ldconfig)|/etc/ld.so.conf /etc/ld.so.conf.d /etc/ld.so.conf.d/*"
        "High|Sourced by root login shells|/etc/profile /etc/profile.d /etc/profile.d/* /etc/bash.bashrc /etc/environment /etc/zsh/zshrc /etc/zsh/zprofile /etc/zsh/zshenv /etc/zsh/zlogin"
        "High|Executed as root on every SSH/console login (pam_motd)|/etc/update-motd.d /etc/update-motd.d/*"
        "High|APT hooks run as root on apt update/install|/etc/apt/apt.conf.d /etc/apt/apt.conf.d/* /etc/apt/sources.list /etc/apt/sources.list.d"
        "High|logrotate postrotate scripts run as root|/etc/logrotate.conf /etc/logrotate.d /etc/logrotate.d/*"
        "High|modprobe install directives run as root|/etc/modprobe.d /etc/modprobe.d/*"
        "High|udev RUN+= rules execute as root|/etc/udev/rules.d /etc/udev/rules.d/*"
        "High|NetworkManager dispatcher scripts run as root|/etc/NetworkManager/dispatcher.d /etc/NetworkManager/dispatcher.d/*"
        "High|sshd configuration (AuthorizedKeysCommand / ForceCommand run as root)|/etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/ssh/sshd_config.d/*"
        "Medium|Desktop session autostart|/etc/xdg/autostart /etc/xdg/autostart/*"
    )
    local spec sev reason globs g f
    for spec in "${specs[@]}"; do
        IFS='|' read -r sev reason globs <<< "$spec"
        for g in $globs; do
            for f in $g; do
                [ -e "$f" ] || continue
                if is_writable "$f"; then
                    ev Path "$f" Why "$reason" How "$W_HOW"
                    add_finding 'Autorun' "Writable privileged hook: $f" "$sev" "$EV" \
                        "$reason. Restore root:root ownership and remove group/other write."
                fi
            done
        done
    done

    # /etc/ld.so.preload present at all is unusual (rootkit indicator)
    if [ -s /etc/ld.so.preload ]; then
        add_finding 'Autorun' '/etc/ld.so.preload is configured' Low "$(cat /etc/ld.so.preload 2>/dev/null)" \
            'Global preloads are rare on servers and a common userland-rootkit technique. Verify each library.'
    fi
    # Library dirs listed in ld.so.conf that are writable
    local libdir
    while IFS= read -r libdir; do
        [[ "$libdir" == /* ]] || continue
        if is_writable "$libdir"; then
            ev LibraryDir "$libdir" How "$W_HOW"
            add_finding 'Autorun' "Writable library directory in ld.so.conf: $libdir" High "$EV" \
                'Plant a library that root/SUID processes load. Fix permissions.'
        fi
    done < <(cat /etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*(#|include|$)' | awk '{print $1}')

    # Other users' dotfiles / ssh dirs
    local i h owner p
    for i in "${!HOME_DIRS[@]}"; do
        h=${HOME_DIRS[$i]}; owner=${HOME_OWNER[$i]}
        [ "$owner" = "$ME" ] && [ "$IS_ROOT" -eq 0 ] && continue
        [ "$h" = "$MY_HOME" ] && [ "$IS_ROOT" -eq 0 ] && continue
        local s=High; [ "$owner" = "root" ] && s=Critical
        for p in "$h" "$h/.bashrc" "$h/.profile" "$h/.bash_profile" "$h/.bash_login" "$h/.zshrc" "$h/.zprofile" \
                 "$h/.ssh" "$h/.ssh/authorized_keys" "$h/.config/autostart" "$h/.pam_environment"; do
            [ -e "$p" ] || [ "$p" = "$h/.ssh/authorized_keys" ] || continue
            if is_writable "$p"; then
                # In root mode the owner owning their own dotfiles is expected
                if [ "$IS_ROOT" -eq 1 ] && [[ "$W_HOW" == *"owned by non-root uid"* ]]; then continue; fi
                ev Account "$owner" Path "$p" How "$W_HOW"
                add_finding 'Autorun' "Writable login file of $owner: $p" "$s" "$EV" \
                    "Code/keys planted here execute or authenticate as $owner. Fix ownership/permissions."
                break
            fi
        done
    done
}
#endregion

#region ---------- PATH ----------
check_path() {
    section "PATH DIRECTORIES"
    local d
    IFS=: read -ra _pd <<< "$ORIG_PATH"
    [[ "$ORIG_PATH" == :* || "$ORIG_PATH" == *: || "$ORIG_PATH" == *::* ]] && _pd+=("")
    declare -A seen=()
    for d in "${_pd[@]}"; do
        [ -n "${seen[x$d]:-}" ] && continue; seen[x$d]=1
        if [ -z "$d" ] || [ "$d" = "." ] || [[ "$d" != /* ]]; then
            add_finding 'PATH' "Relative / current-directory entry in PATH: '${d:-<empty>}'" Medium "PATH: $ORIG_PATH" \
                'Commands resolve against the working directory -> binary planting. Use absolute PATH entries only.'
            continue
        fi
        [ -d "$d" ] || continue
        if is_writable "$d" && [ "$W_PATH" = "$d" ]; then
            ev Directory "$d" How "$W_HOW"
            add_finding 'PATH' "Writable directory on PATH: $d" Medium "$EV" \
                'Writable PATH dir enables binary planting for anything run by name (incl. scripts run by other users). Remove or re-permission.'
        fi
    done
    # System-wide PATH in /etc/environment
    local ep; ep=$(sed -nE 's/^[[:space:]]*PATH[[:space:]]*=[[:space:]]*"?([^"]*)"?.*/\1/p' /etc/environment 2>/dev/null | head -1)
    if [ -n "$ep" ]; then
        IFS=: read -ra _ep <<< "$ep"
        for d in "${_ep[@]}"; do
            [ -d "$d" ] || continue
            if is_writable "$d" && [ "$W_PATH" = "$d" ]; then
                ev Directory "$d" Source /etc/environment How "$W_HOW"
                add_finding 'PATH' "Writable directory in system PATH (/etc/environment): $d" High "$EV" \
                    'Affects every PAM session, including root logins. Fix permissions.'
            fi
        done
    fi
}
#endregion

#region ---------- Containers & sockets ----------
check_containers() {
    section "CONTAINERS & PRIVILEGED SOCKETS"
    local s
    for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /var/run/crio/crio.sock \
             /run/podman/podman.sock /var/snap/lxd/common/lxd/unix.socket /var/lib/lxd/unix.socket \
             /run/incus/unix.socket /var/lib/incus/unix.socket /run/buildkit/buildkitd.sock \
             /var/run/libvirt/libvirt-sock /run/k3s/containerd/containerd.sock; do
        [ -S "$s" ] || continue
        if [ "$IS_ROOT" -eq 0 ] && [ -w "$s" ]; then
            ev Socket "$s" Perms "$(stat -c '%A %U:%G' "$s" 2>/dev/null)"
            add_finding 'Container' "Writable container/VM runtime socket: $s" Critical "$EV" \
                'API access to a root runtime == root on the host (start a privileged container with / mounted).'
        elif [ "$IS_ROOT" -eq 1 ] && _perm_loose "$s"; then
            ev Socket "$s" How "$W_HOW"
            add_finding 'Container' "Runtime socket accessible to non-root: $s" High "$EV" \
                'Restrict the socket to root (and an audited group) only.'
        else
            add_finding 'Container' "Container/VM runtime socket present: $s" Info "Perms: $(stat -c '%A %U:%G' "$s" 2>/dev/null)"
        fi
    done

    if detect_container; then
        local eff; eff=$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null)
        ev Kind "$CONTAINER_KIND" CapEff "$eff"
        add_finding 'Container' "Running inside a container ($CONTAINER_KIND)" Info "$EV"
        if [ "$IS_ROOT" -eq 1 ] && [[ "$eff" =~ ^0*(3f|1ff)f{8}$ ]]; then
            add_finding 'Container' 'Container appears privileged (full capability set)' High "$EV" \
                'Privileged containers can mount host disks / load modules -> host escape.'
        fi
        local dev
        for dev in /dev/sd? /dev/vd? /dev/xvd? /dev/nvme?n?; do
            [ -b "$dev" ] && [ -r "$dev" ] && {
                add_finding 'Container' "Host block device readable in container: $dev" High "Device: $dev" \
                    'Mount or debugfs the host disk -> host file access.'; break; }
        done
        if [ -r /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
            add_finding 'Container' 'Kubernetes service-account token mounted' Medium \
                "Path: /var/run/secrets/kubernetes.io/serviceaccount/token"$'\n'"Namespace: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)" \
                'Check its RBAC (kubectl auth can-i --list). Set automountServiceAccountToken: false where unneeded.'
        fi
    fi

    # NFS exports with no_root_squash (this host as server)
    if [ -r /etc/exports ]; then
        local nrs; nrs=$(grep -vE '^[[:space:]]*#' /etc/exports | grep -E 'no_root_squash|no_all_squash')
        [ -n "$nrs" ] && add_finding 'Container' 'NFS export with no_root_squash' High "$nrs" \
            'Remote root can create SUID-root files on the share -> local root. Use root_squash.'
    fi
    local nfs; nfs=$(grep -E '[[:space:]](nfs4?|cifs|smb3)[[:space:]]' /proc/mounts 2>/dev/null)
    [ -n "$nfs" ] && add_finding 'Container' 'Network filesystems mounted' Info "$nfs"
}
#endregion

#region ---------- Processes ----------
check_processes() {
    section "PROCESSES"
    have ps || return
    # Secrets passed on command lines (visible to all users unless hidepid)
    local hits=""
    while IFS= read -r line; do
        hits+="$(mask "$line")"$'\n'
    done < <(ps -eo user=,pid=,args= 2>/dev/null | grep -iE '(pass(word|wd)?|pwd|secret|token|api[_-]?key)[=:][^[:space:]]|--pass(word)?[=[:space:]][^[:space:]]|sshpass[[:space:]]+-p|mysql[^|]*[[:space:]]-p[^[:space:]]' | grep -v 'grep -iE' | head -20)
    if [ -n "$hits" ]; then
        add_finding 'Process' 'Possible credentials in process command lines' Medium "${hits%$'\n'}" \
            'Command lines are world-readable via /proc unless mounted with hidepid=2. Pass secrets via files/env.'
    fi

    [ "$DEPTH" = "Quick" ] && return
    # Root-owned processes running user-modifiable binaries/scripts
    local user pid args bin tok
    declare -A seen=()
    while read -r user pid args; do
        [ "$user" = "root" ] || continue
        bin=$(readlink -f "/proc/$pid/exe" 2>/dev/null); [ -n "$bin" ] || bin=$(get_bin_path "$args")
        for tok in "$bin" $(path_tokens "${args#*[[:space:]]}"); do
            [[ "$tok" == /* ]] && [ -f "$tok" ] || continue
            [ -n "${seen[$tok]:-}" ] && continue; seen[$tok]=1
            if is_writable "$tok"; then
                ev Pid "$pid" User "$user" Command "$args" Path "$tok" How "$W_HOW"
                add_finding 'Process' "Root process uses a modifiable file: $tok" High "$EV" \
                    'Replace the binary/script and wait for restart -> root. Fix permissions.'
            fi
        done
    done < <(ps -eo user=,pid=,args= 2>/dev/null)
}
#endregion

#region ---------- Kernel hardening (UAC analog) ----------
check_hardening() {
    section "KERNEL HARDENING"
    local aslr ptrace kptr dmesg bpf userns maxns symlinks hardlinks regular fifos suiddump mmapmin
    aslr=$(sysctl_val kernel.randomize_va_space); ptrace=$(sysctl_val kernel.yama.ptrace_scope)
    kptr=$(sysctl_val kernel.kptr_restrict); dmesg=$(sysctl_val kernel.dmesg_restrict)
    bpf=$(sysctl_val kernel.unprivileged_bpf_disabled); userns=$(sysctl_val kernel.unprivileged_userns_clone)
    maxns=$(sysctl_val user.max_user_namespaces)
    symlinks=$(sysctl_val fs.protected_symlinks); hardlinks=$(sysctl_val fs.protected_hardlinks)
    regular=$(sysctl_val fs.protected_regular); fifos=$(sysctl_val fs.protected_fifos)
    suiddump=$(sysctl_val fs.suid_dumpable); mmapmin=$(sysctl_val vm.mmap_min_addr)
    local aa_userns; aa_userns=$(sysctl_val kernel.apparmor_restrict_unprivileged_userns)

    ev randomize_va_space "${aslr:-n/a}" yama.ptrace_scope "${ptrace:-n/a}" kptr_restrict "${kptr:-n/a}" \
       dmesg_restrict "${dmesg:-n/a}" unprivileged_bpf_disabled "${bpf:-n/a}" \
       unprivileged_userns_clone "${userns:-n/a}" max_user_namespaces "${maxns:-n/a}" \
       apparmor_restrict_unprivileged_userns "${aa_userns:-n/a}" \
       protected_symlinks "${symlinks:-n/a}" protected_hardlinks "${hardlinks:-n/a}" \
       protected_regular "${regular:-n/a}" protected_fifos "${fifos:-n/a}" \
       suid_dumpable "${suiddump:-n/a}" mmap_min_addr "${mmapmin:-n/a}"
    local all=$EV
    add_finding 'Hardening' 'Kernel hardening sysctls' Info "$all"

    [ "${aslr:-2}" != "2" ] && add_finding 'Hardening' "ASLR not fully enabled (randomize_va_space=$aslr)" Medium "$all" \
        'Set kernel.randomize_va_space=2.'
    [ "${ptrace:-1}" = "0" ] && add_finding 'Hardening' 'ptrace unrestricted (yama.ptrace_scope=0)' Medium "$all" \
        'Any process can ptrace same-uid processes (credential theft, sudo token reuse). Set kernel.yama.ptrace_scope>=1.'
    [ "${kptr:-1}" = "0" ] && add_finding 'Hardening' 'Kernel pointers exposed (kptr_restrict=0)' Low "$all" \
        'Leaks kernel addresses that defeat KASLR. Set kernel.kptr_restrict=1.'
    [ "${dmesg:-1}" = "0" ] && add_finding 'Hardening' 'dmesg readable by unprivileged users (dmesg_restrict=0)' Low "$all" \
        'Kernel log leaks addresses/hardware info. Set kernel.dmesg_restrict=1.'
    [ "${bpf:-1}" = "0" ] && add_finding 'Hardening' 'Unprivileged eBPF allowed (unprivileged_bpf_disabled=0)' Medium "$all" \
        'Unprivileged BPF is a recurring kernel-LPE surface. Set kernel.unprivileged_bpf_disabled=1 (or 2).'
    if [ "${userns:-}" = "1" ] && [ "${aa_userns:-0}" != "1" ] && [ "${maxns:-0}" != "0" ]; then
        add_finding 'Hardening' 'Unprivileged user namespaces allowed' Low "$all" \
            'User namespaces expose more kernel attack surface to unprivileged users. Restrict if not needed.'
    fi
    { [ "${symlinks:-1}" = "0" ] || [ "${hardlinks:-1}" = "0" ]; } && \
        add_finding 'Hardening' 'Symlink/hardlink protection disabled' Medium "$all" \
            'Enables /tmp symlink races against root. Set fs.protected_symlinks=1 and fs.protected_hardlinks=1.'
    [ "${regular:-1}" = "0" ] && add_finding 'Hardening' 'fs.protected_regular=0' Low "$all" \
        'Set fs.protected_regular=2 to block O_CREAT races in world-writable sticky dirs.'
    [ "${suiddump:-0}" = "1" ] && add_finding 'Hardening' 'SUID core dumps enabled (fs.suid_dumpable=1)' Medium "$all" \
        'Core dumps of SUID processes may leak privileged memory. Set fs.suid_dumpable=0.'
    [ "${mmapmin:-65536}" = "0" ] && add_finding 'Hardening' 'vm.mmap_min_addr=0 (NULL page mappable)' Medium "$all" \
        'Enables NULL-dereference kernel exploits. Set vm.mmap_min_addr=65536.'

    # /tmp, /dev/shm mount options
    local mnt opts
    for mnt in /tmp /dev/shm /var/tmp; do
        opts=$(awk -v m="$mnt" '$2==m{print $4}' /proc/mounts 2>/dev/null | tail -1)
        [ -n "$opts" ] || continue
        if [[ ",$opts," != *,noexec,* ]] || [[ ",$opts," != *,nosuid,* ]]; then
            add_finding 'Hardening' "$mnt mounted without noexec/nosuid" Info "Mount options: $opts" \
                'Hardening only: noexec,nosuid,nodev on world-writable mounts limits staging.'
        fi
    done
}
#endregion

#region ---------- Defensive tooling (AV analog) ----------
check_defenses() {
    section "DEFENSIVE TOOLING"
    local aa="n/a" se="n/a" fw="n/a" audit="no" agents="" p
    [ -r /sys/module/apparmor/parameters/enabled ] && aa=$(cat /sys/module/apparmor/parameters/enabled)
    if have getenforce; then se=$(getenforce 2>/dev/null); elif [ -r /sys/fs/selinux/enforce ]; then se="enforce=$(cat /sys/fs/selinux/enforce)"; fi
    [ -r /etc/ufw/ufw.conf ] && fw="ufw $(sed -n 's/^ENABLED=//p' /etc/ufw/ufw.conf)"
    have pgrep && pgrep -x auditd >/dev/null 2>&1 && audit="yes"
    for p in falcon-sensor wdavdaemon mdatp clamd freshclam wazuh-agentd ossec-agentd osqueryd \
             sentinelone-agent s1-agent cbagentd cbdaemon elastic-agent elastic-endpoint auditbeat \
             falco tetragon sysmon qualys-cloud-agent cylancesvc xagt taniumclient rapid7_agent ir_agent \
             fail2ban-server aide tripwire; do
        have pgrep && pgrep -x "$p" >/dev/null 2>&1 && agents+="$p "
    done
    ev AppArmor "$aa" SELinux "$se" Firewall "$fw" auditd "$audit" Agents "${agents:-none detected}"
    add_finding 'Defense' 'Security tooling status' Info "$EV"
    if [ "$aa" != "Y" ] && [[ "$se" != Enforcing* ]] && [ "$se" != "enforce=1" ]; then
        add_finding 'Defense' 'No mandatory access control enforcing (AppArmor/SELinux)' Low "$EV" \
            'MAC confines compromised services. Enable AppArmor (Ubuntu default) or SELinux.'
    fi
    if [ -z "$agents" ] && [ "$audit" = "no" ]; then
        add_finding 'Defense' 'No EDR / audit agent detected' Low "$EV" \
            'Activity on this host is unlikely to be detected. Note for the report; confirm with the client.'
    fi
}
#endregion

#region ---------- Credential exposure ----------
check_credentials() {
    section "CREDENTIAL EXPOSURE"
    local f i h owner p

    # Shadow and its backups
    if [ "$IS_ROOT" -eq 0 ]; then
        for f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow- /etc/security/opasswd \
                 /var/backups/shadow.bak /var/backups/gshadow.bak /etc/master.passwd; do
            if [ -f "$f" ] && [ -r "$f" ]; then
                add_finding 'Credential' "Readable password hash file: $f" High "Path: $f"$'\n'"Perms: $(stat -c '%A %U:%G' "$f")" \
                    'Hashes allow offline cracking. Restrict to root:shadow 0640.'
            fi
        done
    else
        for f in /etc/shadow /etc/gshadow /etc/shadow- /var/backups/shadow.bak; do
            if [ -f "$f" ]; then
                local m; m=$(stat -c '%a' "$f"); 
                if [ $(( 8#$m & 8#004 )) -ne 0 ]; then
                    add_finding 'Credential' "World-readable password hash file: $f" High "Perms: $(stat -c '%A %U:%G' "$f")" \
                        'Restrict to root:shadow 0640.'
                fi
            fi
        done
    fi

    local empty
    empty=$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null)
    [ -n "$empty" ] && add_finding 'Credential' 'Accounts with an empty password in /etc/shadow' High "$empty" \
        'Empty passwords allow login/su without a password where PAM permits nullok. Lock or set passwords.'

    # Cleartext credential files in readable home dirs
    local cred_files=(.aws/credentials .aws/config .azure/accessTokens.json .azure/msal_token_cache.json
        .config/gcloud/credentials.db .config/gcloud/application_default_credentials.json
        .config/gcloud/legacy_credentials .kube/config .docker/config.json .git-credentials .netrc
        .pgpass .my.cnf .npmrc .pypirc .config/gh/hosts.yml .terraform.d/credentials.tfrc.json
        .vault-token .s3cfg .boto .config/rclone/rclone.conf .smbcredentials .ldaprc .gnupg/private-keys-v1.d
        .password-store .local/share/keyrings .mozilla/firefox .config/google-chrome .config/chromium
        .config/filezilla/recentservers.xml .config/filezilla/sitemanager.xml .remmina)
    for i in "${!HOME_DIRS[@]}"; do
        h=${HOME_DIRS[$i]}; owner=${HOME_OWNER[$i]}
        local mine=0; [ "$h" = "$MY_HOME" ] && mine=1
        for p in "${cred_files[@]}"; do
            f="$h/$p"
            [ -e "$f" ] && [ -r "$f" ] || continue
            local sev=Medium title="Credential material: ~$owner/$p"
            if [ $mine -eq 0 ] && [ "$IS_ROOT" -eq 0 ]; then sev=High; title="Another user's credential material is readable: $f"; fi
            ev Path "$f" Owner "$owner" Perms "$(stat -c '%A %U:%G' "$f" 2>/dev/null)"
            add_finding 'Credential' "$title" "$sev" "$EV" \
                'Tokens/keys at rest; may enable pivot to cloud, registries, databases or other hosts. Confirm scope; rotate and restrict to 0600.'
        done

        # SSH private keys
        local k
        for k in "$h"/.ssh/*; do
            [ -f "$k" ] && [ -r "$k" ] || continue
            head -c 64 "$k" 2>/dev/null | grep -q 'PRIVATE KEY' || continue
            local enc="no"
            if grep -q 'ENCRYPTED' "$k" 2>/dev/null; then enc="yes"
            elif grep -q 'BEGIN OPENSSH PRIVATE KEY' "$k" 2>/dev/null && \
                 sed '1d;$d' "$k" | tr -d '\n' | base64 -d 2>/dev/null | head -c 64 | grep -qa 'bcrypt'; then enc="yes"; fi
            local sev=Low title="SSH private key: $k"
            [ "$enc" = "no" ] && sev=Medium
            if [ $mine -eq 0 ] && [ "$IS_ROOT" -eq 0 ]; then sev=High; title="Another user's SSH private key is readable: $k"; fi
            ev Path "$k" Owner "$owner" Passphrase "$enc" Perms "$(stat -c '%A %U:%G' "$k")"
            add_finding 'Credential' "$title" "$sev" "$EV" \
                'Check ~/.ssh/known_hosts and config for reachable hosts. Protect keys with a passphrase and 0600 perms.'
        done
        if [ -r "$h/.ssh/known_hosts" ] && [ $mine -eq 0 ] && [ "$IS_ROOT" -eq 0 ]; then
            add_finding 'Credential' "Readable known_hosts of $owner" Low "Path: $h/.ssh/known_hosts" \
                'Reveals lateral-movement targets.'
        fi

        # Shell / client histories
        local hf
        for hf in .bash_history .zsh_history .sh_history .ash_history .history .mysql_history .psql_history \
                  .python_history .rediscli_history .sqlite_history .node_repl_history .lesshst .viminfo; do
            f="$h/$hf"
            [ -f "$f" ] && [ -r "$f" ] || continue
            local n
            n=$(grep -ciE 'pass(word|wd)?|pwd=|-p[^[:space:]]|secret|token|api[_-]?key|sshpass|AKIA|BEGIN .*PRIVATE|chpasswd|htpasswd|curl[^|]*-u ' "$f" 2>/dev/null)
            if [ "${n:-0}" -gt 0 ]; then
                local sev=Medium; [ $mine -eq 0 ] && [ "$IS_ROOT" -eq 0 ] && sev=High
                ev File "$f" Owner "$owner" MatchCount "$n"
                add_finding 'Credential' "Secrets-like entries in history: $f" "$sev" "$EV" \
                    'Histories retain cleartext secrets typed on the command line. Clear them; avoid inline secrets (HISTCONTROL=ignorespace).'
            elif [ $mine -eq 0 ] && [ "$IS_ROOT" -eq 0 ]; then
                add_finding 'Credential' "Another user's history file is readable: $f" Low "File: $f" \
                    'History files should be 0600.'
            fi
        done
    done

    # Readable root-only host secrets
    for f in /etc/ssh/ssh_host_*_key /etc/mysql/debian.cnf /etc/mysql/my.cnf /root/.my.cnf \
             /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/vendor-data.txt \
             /etc/openvpn/*.key /etc/openvpn/*auth* /etc/ipsec.secrets /etc/ppp/chap-secrets /etc/ppp/pap-secrets \
             /etc/krb5.keytab /etc/ldap.secret /etc/pam_ldap.conf /etc/sssd/sssd.conf /etc/samba/smbpasswd \
             /var/lib/samba/private/secrets.tdb /etc/postfix/sasl_passwd /etc/msmtprc /etc/fetchmailrc \
             /etc/letsencrypt/live/*/privkey.pem /etc/ssl/private/*.key /etc/ssl/private/*.pem \
             /etc/rancher/k3s/k3s.yaml /etc/kubernetes/admin.conf /etc/kubernetes/pki/*.key \
             /var/lib/jenkins/secrets/master.key /var/lib/jenkins/credentials.xml /etc/gitlab/gitlab-secrets.json \
             /etc/vault.d/*.hcl /etc/cups/printers.conf; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        if [ "$IS_ROOT" -eq 1 ]; then
            local m; m=$(stat -c '%a' "$f")
            [ $(( 8#$m & 8#004 )) -eq 0 ] && continue
        fi
        case "$f" in /etc/mysql/my.cnf|/etc/cups/printers.conf|/etc/pam_ldap.conf)
            grep -qiE '^[[:space:]]*(password|bindpw|AuthInfoRequired)' "$f" 2>/dev/null || continue ;;
        esac
        ev Path "$f" Perms "$(stat -c '%A %U:%G' "$f" 2>/dev/null)"
        add_finding 'Credential' "Sensitive root-owned secret is readable: $f" High "$EV" \
            'Host keys, service passwords, keytabs and private TLS keys must be root-only (0600/0640).'
    done

    # cloud-init output and fstab credentials
    if [ -r /var/log/cloud-init-output.log ] && grep -qiE 'password|passwd|secret|token' /var/log/cloud-init-output.log 2>/dev/null; then
        add_finding 'Credential' 'Secrets-like strings in cloud-init output log' Medium "File: /var/log/cloud-init-output.log" \
            'Provisioning output often echoes generated passwords/tokens. Review and restrict.'
    fi
    local fst; fst=$(grep -vE '^[[:space:]]*#' /etc/fstab 2>/dev/null | grep -iE '(password|pass|credentials)=')
    if [ -n "$fst" ]; then
        local masked=""; while IFS= read -r l; do masked+="$(printf '%s' "$l" | sed -E 's/(password|pass)=[^,[:space:]]+/\1=****/Ig')"$'\n'; done <<< "$fst"
        add_finding 'Credential' 'Credentials referenced in /etc/fstab' Medium "${masked%$'\n'}" \
            'Inline passwords in world-readable fstab; use a root-only credentials= file.'
        local cf
        for cf in $(printf '%s' "$fst" | grep -oiE 'credentials=[^,[:space:]]+' | cut -d= -f2); do
            [ -r "$cf" ] && [ "$IS_ROOT" -eq 0 ] && add_finding 'Credential' "Readable mount credentials file: $cf" High "Path: $cf" \
                'Restrict to root 0600.'
        done
    fi

    # sshd configuration posture
    local sshd; sshd=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*#')
    if [ -n "$sshd" ]; then
        printf '%s' "$sshd" | grep -qiE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+yes' && \
            add_finding 'Credential' 'sshd PermitEmptyPasswords yes' High 'PermitEmptyPasswords yes' 'Set PermitEmptyPasswords no.'
        printf '%s' "$sshd" | grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+yes' && \
            add_finding 'Credential' 'sshd PermitRootLogin yes' Low 'PermitRootLogin yes' 'Use prohibit-password or no.'
    fi

    # SSH agent sockets of other users
    local sock
    for sock in /tmp/ssh-*/agent.* /run/user/*/keyring/ssh /run/user/*/gnupg/S.gpg-agent.ssh; do
        [ -S "$sock" ] || continue
        [ -O "$sock" ] && continue
        if [ -w "$sock" ] || [ "$IS_ROOT" -eq 1 ]; then
            ev Socket "$sock" Owner "$(stat -c '%U' "$sock" 2>/dev/null)"
            add_finding 'Credential' "Usable SSH agent socket of another user: $sock" "$([ $IS_ROOT -eq 1 ] && echo Info || echo High)" "$EV" \
                'Hijack the agent (SSH_AUTH_SOCK) to authenticate as that user to other hosts.'
        fi
    done

    # Wi-Fi PSKs (WLAN analog)
    local wl=""
    for f in /etc/NetworkManager/system-connections/* /etc/wpa_supplicant/*.conf /etc/netplan/*.yaml; do
        [ -f "$f" ] || continue
        if [ -r "$f" ] && grep -qiE '^[[:space:]]*(psk|password|wpa-psk)[[:space:]]*[:=]' "$f" 2>/dev/null; then
            if [ "$IS_ROOT" -eq 0 ] || [ $(( 8#$(stat -c '%a' "$f") & 8#004 )) -ne 0 ]; then
                add_finding 'Credential' "Readable WLAN/network secret: $f" Medium "Path: $f"$'\n'"Perms: $(stat -c '%A %U:%G' "$f")" \
                    'Network PSKs/802.1X passwords should be root-only (0600).'
            fi
        else
            wl+="$f"$'\n'
        fi
    done
    [ -n "$wl" ] && add_finding 'Credential' 'Saved network profiles (root-readable)' Info "${wl%$'\n'}"

    # Standard+: common application configs
    if [ "$DEPTH" != "Quick" ]; then
        local apps=()
        mapfile -d '' apps < <(find /var/www /srv /opt /home /usr/local /etc -maxdepth 6 \
            \( -name node_modules -o -name .git -o -name vendor -o -name site-packages \) -prune -o -type f \
            \( -name wp-config.php -o -name '.env' -o -name 'settings.py' -o -name 'database.yml' -o -name 'config.php' \
               -o -name 'configuration.php' -o -name 'LocalSettings.php' -o -name 'web.config' -o -name 'appsettings*.json' \
               -o -name 'application.properties' -o -name 'application.yml' -o -name 'docker-compose*.yml' \
               -o -name '.htpasswd' -o -name 'tomcat-users.xml' -o -name 'standalone.xml' -o -name 'server.xml' \
               -o -name 'jenkins.xml' -o -name '*.ovpn' -o -name '*.kdbx' -o -name '*.tfstate' \) \
            -readable -print0 2>/dev/null)
        for f in "${apps[@]}"; do
            local n; n=$(grep -ciE '(pass(word|wd)?|pwd|secret|api[_-]?key|token|DB_PASS)["'"'"']?[[:space:]]*[:=,>]|BEGIN .*PRIVATE KEY|<user[^>]*password=' "$f" 2>/dev/null)
            case "$f" in *.kdbx|*.htpasswd|*.tfstate) n=${n:-1}; [ "$n" -gt 0 ] || n=1 ;; esac
            [ "${n:-0}" -gt 0 ] || continue
            local sev=Medium; case "$f" in *wp-config.php|*/.env|*.htpasswd|*tomcat-users.xml|*.tfstate|*.kdbx) sev=High ;; esac
            ev Path "$f" Perms "$(stat -c '%A %U:%G' "$f" 2>/dev/null)" MatchingLines "$n"
            add_finding 'Credential' "Application config with credentials: $f" "$sev" "$EV" \
                'App/DB credentials at rest. Verify, rotate if exposed, restrict permissions or move to a secrets store.'
        done
    fi
}
#endregion

#region ---------- Writable sensitive files sweep ----------
check_writable_sweep() {
    [ "$DEPTH" = "Quick" ] && return
    section "WRITABLE FILES SWEEP"
    local roots=(/etc /opt /srv /usr/local)
    [ "$DEPTH" = "Deep" ] && roots=(/etc /opt /srv /usr /boot /bin /sbin /lib /lib32 /lib64 /var /root /home)
    local existing=() r; for r in "${roots[@]}"; do [ -d "$r" ] && [ ! -L "$r" ] && existing+=("$r"); done
    local prune=( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/tmp -o -path /var/crash
                  -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/php/sessions
                  -o -path /var/spool/postfix -o -path /var/mail -o -path /var/lib/lxcfs -o -path /var/cache )
    [ -n "$MY_HOME" ] && prune+=( -o -path "$MY_HOME" )
    local test=( -writable ! -user "$MY_UID" )
    [ "$IS_ROOT" -eq 1 ] && test=( -perm -o+w )
    local files=() f
    mapfile -d '' files < <(find "${existing[@]}" \( "${prune[@]}" \) -prune -o \( -type f -o -type d \) \
        "${test[@]}" ! -perm -1000 -print0 2>/dev/null)

    local high=0 other="" ocount=0
    for f in "${files[@]}"; do
        case "$f" in
            /etc/*|/usr/*|/bin/*|/sbin/*|/lib*|/boot/*|/root/*)
                if [ $high -lt 50 ]; then
                    ev Path "$f" Perms "$(stat -c '%A %U:%G' "$f" 2>/dev/null)"
                    add_finding 'Writable' "Writable system path: $f" High "$EV" \
                        'System files/dirs modifiable by non-root users enable config or binary tampering. Fix ownership/permissions.'
                fi
                high=$((high + 1)) ;;
            *)
                ocount=$((ocount + 1))
                [ $ocount -le 50 ] && other+="$(stat -c '%A %U:%G' "$f" 2>/dev/null) $f"$'\n' ;;
        esac
    done
    [ $high -gt 50 ] && add_finding 'Writable' "$((high - 50)) more writable system paths not listed" High '' 'Re-run the sweep manually for the full list.'
    local what="writable files/dirs owned by other users"; [ "$IS_ROOT" -eq 1 ] && what="world-writable files/dirs"
    [ $ocount -gt 0 ] && add_finding 'Writable' "$ocount $what outside system paths (first 50 shown)" Medium "${other%$'\n'}" \
        'Review for scripts, configs or data consumed by other users or privileged jobs.'
}
#endregion

#region ---------- Secret / credential file scan (opt-in) ----------

# Regex bank: name | severity | flags (i = case-insensitive) | ERE (GNU grep -E).
# Tuned to flag assignments and well-formed secret tokens rather than any hex blob.
SQ="'"
Q="[${SQ}\"]"            # a quote character
NQ="[^[:space:]${SQ}\"]" # not whitespace / quote
SP_NAME=(); SP_SEV=(); SP_FLAG=(); SP_RX=()
addpat() { SP_NAME+=("$1"); SP_SEV+=("$2"); SP_FLAG+=("$3"); SP_RX+=("$4"); }

# --- Generic credential assignments ---
addpat 'Password assignment'        High   i "(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*${Q}?${NQ}{3,}"
addpat 'Secret assignment'          High   i "(secret|client[_-]?secret|api[_-]?secret)[[:space:]]*[:=][[:space:]]*${Q}?${NQ}{6,}"
addpat 'API key assignment'         Medium i "(api[_-]?key|apikey|access[_-]?key|x-api-key)[[:space:]]*[:=][[:space:]]*${Q}?[A-Za-z0-9/+_-]{8,}"
addpat 'Token assignment'           Medium i "(auth[_-]?token|access[_-]?token|bearer|refresh[_-]?token)[[:space:]]*[:=][[:space:]]*${Q}?[A-Za-z0-9._-]{8,}"
addpat 'Username assignment'        Low    i "(username|user|login|uid)[[:space:]]*[:=][[:space:]]*${Q}?${NQ}{2,}"
# --- Connection strings ---
addpat 'DB connection string pwd'   High   i "(password|pwd)[[:space:]]*=[[:space:]]*[^;${SQ}\"[:space:]]{3,}[[:space:]]*;"
addpat 'ODBC/JDBC connstr'          Medium i '(data source|server|initial catalog|database)[[:space:]]*=[^;]+;.*(user id|uid)[[:space:]]*='
addpat 'URI with inline credentials' High  i '[a-z][a-z0-9+.-]{1,15}://[^:/@[:space:]]+:[^@/[:space:]]+@'
# --- Private keys ---
addpat 'Private key block'          High   '' '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----'
addpat 'PuTTY private key'          High   '' 'PuTTY-User-Key-File-[0-9]'
# --- JWT ---
addpat 'JSON Web Token'             Medium '' 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'
# --- Cloud / vendor keys ---
addpat 'AWS Access Key ID'          High   '' '\b(AKIA|ASIA|A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b'
addpat 'AWS Secret Access Key'      High   i "aws.{0,20}(secret|access).{0,20}${Q}[0-9a-zA-Z/+]{40}${Q}"
addpat 'Google API Key'             Medium '' '\bAIza[0-9A-Za-z_-]{35}\b'
addpat 'Slack token'                High   '' '\bxox[baprs]-[0-9A-Za-z-]{10,}'
addpat 'GitHub token'               High   '' '\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}'
addpat 'GitLab PAT'                 High   '' '\bglpat-[0-9A-Za-z_-]{20}'
addpat 'Stripe key'                 High   '' '\b(sk|rk)_(live|test)_[0-9a-zA-Z]{20,}'
addpat 'Twilio key'                 Medium '' '\bSK[0-9a-fA-F]{32}\b'
addpat 'SendGrid key'               Medium '' '\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b'
addpat 'Azure storage key'          High   i '(accountkey|sharedaccesssignature)[[:space:]]*=[[:space:]]*[^;[:space:]]{20,}'
addpat 'HashiCorp Vault token'      High   '' '\bhvs\.[A-Za-z0-9_-]{24,}'
addpat 'npm token'                  High   '' '\bnpm_[A-Za-z0-9]{36}\b'
addpat 'LLM provider API key'       Medium '' '\bsk-(ant-|proj-)?[A-Za-z0-9_-]{32,}'
addpat 'Docker registry auth'       High   '' '"auth"[[:space:]]*:[[:space:]]*"[A-Za-z0-9+/=]{12,}"'
addpat 'PFX/P12 reference'          Low    i "\.(pfx|p12)(${Q}|[[:space:];])"
# --- Linux-specific leftovers ---
addpat 'Unix crypt / htpasswd hash' High   '' '\$(1|2[abxy]?|5|6|y|gy|7|apr1)\$[./A-Za-z0-9$]{8,}'
addpat 'sshpass inline password'    High   '' 'sshpass[[:space:]]+-p[[:space:]]*[^[:space:]]+'
addpat 'Password on command line'   Medium i '(mysql|mysqldump|mariadb|psql|mongosh?|redis-cli|smbclient|ldapsearch|sqlcmd)[^|;&]*[[:space:]](-p[^[:space:]-][^[:space:]]*|--pass(word)?[= ][^[:space:]]+|-a[[:space:]]+[^[:space:]]+)'
addpat 'curl/wget basic auth'       Medium i '(curl[^|;&]*[[:space:]](-u|--user)[[:space:]]*[^[:space:]:]+:[^[:space:]]+|wget[^|;&]*--(http-)?password[= ][^[:space:]]+)'
addpat 'Password piped to sudo -S'  Medium '' 'echo[[:space:]].+\|[[:space:]]*sudo[[:space:]]+(-[a-zA-Z]*)?-S'
addpat 'chpasswd / useradd -p'      Medium '' '(chpasswd|usermod[[:space:]].*-p[[:space:]]|useradd[[:space:]].*-p[[:space:]]|passwd[[:space:]]+--stdin)'
addpat 'WPA PSK'                    Medium i '^[[:space:]]*(wpa-)?psk[[:space:]]*[:=][[:space:]]*[^[:space:]]{8,}'

check_secret_scan() {
    [ "$SECRET_SCAN" -eq 1 ] || return
    section "SECRET / CREDENTIAL FILE SCAN"

    local roots=()
    if [ ${#SCAN_ROOTS[@]} -gt 0 ]; then
        roots=("${SCAN_ROOTS[@]}")
    elif [ "$DEPTH" = "Deep" ]; then
        roots=(/)
    else
        roots=(/etc /opt /srv /var/www /var/backups /var/opt /var/lib/jenkins /usr/local/etc /home /root /tmp /var/tmp /dev/shm /mnt /media)
        [ -n "$MY_HOME" ] && roots+=("$MY_HOME")
    fi
    local existing=() r; declare -A seen=()
    for r in "${roots[@]}"; do
        [ -d "$r" ] && [ -r "$r" ] || continue
        [ -n "${seen[$r]:-}" ] && continue; seen[$r]=1; existing+=("$r")
    done
    [ ${#existing[@]} -gt 0 ] || { add_finding 'SecretScan' 'Secret scan: no readable roots' Info; return; }

    # Candidate files: config/code/secret-bearing text, size-limited, noisy trees pruned
    local names=( '*.conf' '*.cnf' '*.cfg' '*.config' '*.ini' '*.xml' '*.json' '*.yml' '*.yaml' '*.toml'
        '*.txt' '*.env' '.env' '.env.*' '*.properties' '*.sh' '*.bash' '*.zsh' '*.py' '*.rb' '*.pl' '*.php'
        '*.js' '*.ts' '*.go' '*.java' '*.cs' '*.sql' '*.log' '*.bak' '*.old' '*.orig' '*.save' '*.pem' '*.key'
        '*.ppk' '*.ovpn' '*.tf' '*.tfvars' '*.tfstate' '*.service' '*.htpasswd' '.htpasswd' '.netrc' '.git-credentials'
        '.pgpass' '.my.cnf' '.npmrc' '.pypirc' '.s3cfg' 'id_rsa' 'id_dsa' 'id_ecdsa' 'id_ed25519' '*_history'
        '.*_history' 'credentials' 'Dockerfile' '*.secret' '*.credentials' 'wp-config.php' )
    local nexpr=() n
    for n in "${names[@]}"; do nexpr+=( -o -name "$n" ); done
    nexpr=( "${nexpr[@]:1}" )
    local prune=( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /boot
                  -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /usr/share -o -path /usr/lib
                  -o -path /usr/src -o -path /usr/include -o -path /lib -o -path /lib32 -o -path /lib64
                  -o -path /var/cache -o -path /var/lib/apt -o -path /var/lib/dpkg -o -name node_modules
                  -o -name .git -o -name __pycache__ -o -name site-packages -o -name dist-packages -o -name .cache )
    local raw=() files=() f
    mapfile -d '' raw < <(find "${existing[@]}" \( "${prune[@]}" \) -prune -o -type f \( "${nexpr[@]}" \) \
        -size -"$((MAX_KB + 1))"k ! -name 'PrivEscAudit_*' ! -name nsswitch.conf ! -name debconf.conf \
        ! -name login.defs ! -name adduser.conf ! -name deluser.conf ! -name 'dpkg.log*' ! -path '/var/log/apt/*' \
        ! -name 'alternatives.log*' ! -name bootstrap.log -readable -print0 2>/dev/null)
    declare -A seen_file=()
    for f in "${raw[@]}"; do      # overlapping roots (/home + $HOME) and this script itself
        [ "$f" = "$SELF" ] && continue
        [ -n "${seen_file[$f]:-}" ] && continue; seen_file[$f]=1; files+=("$f")
    done
    local scanned=${#files[@]} matched=0 idx

    if [ "$scanned" -gt 0 ]; then
        for idx in "${!SP_RX[@]}"; do
            local flag=(); [ "${SP_FLAG[$idx]}" = "i" ] && flag=(-i)
            local rx=${SP_RX[$idx]}
            # Pass 1: which files match (one grep pass per pattern over all files)
            while IFS= read -r -d '' f; do
                local cnt samples="" s
                cnt=$(grep -EoI "${flag[@]}" -- "$rx" "$f" 2>/dev/null | wc -l)
                [ "$cnt" -gt 0 ] || continue
                matched=$((matched + 1))
                while IFS= read -r s; do samples+="$(mask "$s") | "; done < <(grep -EoI "${flag[@]}" -- "$rx" "$f" 2>/dev/null | head -3)
                ev File "$f" Pattern "${SP_NAME[$idx]}" Hits "$cnt" MaskedSample "${samples% | }"
                add_finding 'SecretScan' "${SP_NAME[$idx]} in ${f##*/}" "${SP_SEV[$idx]}" "$EV" \
                    'Possible secret at rest. Verify, then remove from file / move to a secrets store.'
            done < <(printf '%s\0' "${files[@]}" | xargs -0 grep -lIZE "${flag[@]}" -- "$rx" 2>/dev/null)
        done
    fi
    local IFS=';'
    ev Roots "${existing[*]}" FilesScanned "$scanned" Hits "$matched"
    unset IFS
    add_finding 'SecretScan' "Secret scan complete: $scanned files scanned, $matched pattern hits" Info "$EV"
}
#endregion

#region ---------- Network snapshot ----------
check_network() {
    section "NETWORK"
    local listen=""
    if have ss; then listen=$(ss -H -tuln 2>/dev/null | awk '{print $1, $5}' | sort -u)
    elif have netstat; then listen=$(netstat -tuln 2>/dev/null | awk 'NR>2{print $1, $4}' | sort -u)
    fi
    if [ -n "$listen" ]; then
        add_finding 'Network' 'Listening TCP/UDP ports' Info "$listen"
        local lo; lo=$(printf '%s\n' "$listen" | grep -E '[[:space:]](127\.[0-9.]+|\[::1\]|::1):[0-9]+$')
        [ -n "$lo" ] && add_finding 'Network' 'Localhost-only services (not reachable remotely; local pivot targets)' Info "$lo" \
            'Loopback services (DBs, admin panels, debug ports) are often unauthenticated. Review each.'
    fi
    if have ip; then
        add_finding 'Network' 'Interfaces' Info "$(ip -brief addr 2>/dev/null || ip addr 2>/dev/null)"
    fi
    if [ -r /etc/hosts ]; then
        local hosts; hosts=$(grep -vE '^[[:space:]]*(#|$)' /etc/hosts | grep -vE '^(127\.0\.[01]\.1|::1|fe00|ff0[0-2])')
        [ -n "$hosts" ] && add_finding 'Network' 'Custom /etc/hosts entries' Info "$hosts"
    fi
}
#endregion

#region ---------- Reporting ----------
json_escape() {
    local s=$1
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
    s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037\177')
    printf '%s' "$s"
}
html_escape() {
    local s=$1
    s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; s=${s//\"/&quot;}; s=${s//\'/&#39;}
    printf '%s' "$s"
}
csv_field() { local s=${1//\"/\"\"}; printf '"%s"' "$s"; }

# Indices of findings >= MinSeverity, sorted Critical -> Info (stable)
ordered_indices() {
    local min=${SEV_RANK[$MIN_SEV]} r i
    ORDER=()
    for r in 4 3 2 1 0; do
        [ "$r" -ge "$min" ] || continue
        for i in "${!F_SEV[@]}"; do [ "${SEV_RANK[${F_SEV[$i]}]}" -eq "$r" ] && ORDER+=("$i"); done
    done
}

export_report() {
    ordered_indices
    local i s
    declare -A counts=([Critical]=0 [High]=0 [Medium]=0 [Low]=0 [Info]=0)
    for s in "${F_SEV[@]}"; do counts[$s]=$(( ${counts[$s]} + 1 )); done

    if has_format console; then
        section "SUMMARY"
        for s in Critical High Medium Low Info; do
            printf '%s%-9s: %s%s\n' "${SEV_COLOR[$s]}" "$s" "${counts[$s]}" "$C_RESET"
        done
        echo
        for i in "${ORDER[@]}"; do
            s=${F_SEV[$i]}
            [ "${SEV_RANK[$s]}" -ge 1 ] || continue
            printf '%s[%s] %s / %s%s\n' "${SEV_COLOR[$s]}" "$s" "${F_CAT[$i]}" "${F_TITLE[$i]}" "$C_RESET"
            if [ "${SEV_RANK[$s]}" -ge 3 ] && [ -n "${F_EVID[$i]}" ]; then
                printf '%s\n' "${F_EVID[$i]}" | head -4 | sed "s/^/    | /"
            fi
            [ -n "${F_REM[$i]}" ] && printf '%s    -> %s%s\n' "$C_GRAY" "${F_REM[$i]}" "$C_RESET"
        done
        echo
        printf '%sCompleted in %ss. %s findings total.%s\n' "$C_CYAN" "$((SECONDS - START_SECONDS))" "${#F_SEV[@]}" "$C_RESET"
    fi

    local stamp base
    printf -v stamp '%(%Y%m%d-%H%M%S)T' -1
    base="${OUTPUT_PATH%/}/PrivEscAudit_${HOST}_${stamp}"
    umask 077   # reports contain sensitive evidence

    if has_format json; then
        {
            printf '[\n'
            local first=1
            for i in "${ORDER[@]}"; do
                [ $first -eq 1 ] || printf ',\n'; first=0
                printf '  {"Category":"%s","Title":"%s","Severity":"%s","SevRank":%s,"Evidence":"%s","Remediation":"%s","Timestamp":"%s"}' \
                    "$(json_escape "${F_CAT[$i]}")" "$(json_escape "${F_TITLE[$i]}")" "${F_SEV[$i]}" \
                    "${SEV_RANK[${F_SEV[$i]}]}" "$(json_escape "${F_EVID[$i]}")" \
                    "$(json_escape "${F_REM[$i]}")" "${F_TS[$i]}"
            done
            printf '\n]\n'
        } > "$base.json"
        has_format console && printf '%sJSON report: %s%s\n' "$C_GREEN" "$base.json" "$C_RESET"
    fi
    if has_format csv; then
        {
            printf 'Severity,Category,Title,Remediation,Evidence,Timestamp\n'
            for i in "${ORDER[@]}"; do
                printf '%s,%s,%s,%s,%s,%s\n' "$(csv_field "${F_SEV[$i]}")" "$(csv_field "${F_CAT[$i]}")" \
                    "$(csv_field "${F_TITLE[$i]}")" "$(csv_field "${F_REM[$i]}")" \
                    "$(csv_field "${F_EVID[$i]}")" "$(csv_field "${F_TS[$i]}")"
            done
        } > "$base.csv"
        has_format console && printf '%sCSV report: %s%s\n' "$C_GREEN" "$base.csv" "$C_RESET"
    fi
    if has_format html; then
        export_html "$base.html"
        has_format console && printf '%sHTML report: %s%s\n' "$C_GREEN" "$base.html" "$C_RESET"
    fi
}

export_html() {
    local path=$1 i s
    declare -A bg=([Critical]='#7f1d1d' [High]='#b91c1c' [Medium]='#b45309' [Low]='#4d7c0f' [Info]='#334155')
    local counts=""
    declare -A c=([Critical]=0 [High]=0 [Medium]=0 [Low]=0 [Info]=0)
    for s in "${F_SEV[@]}"; do c[$s]=$(( ${c[$s]} + 1 )); done
    for s in Critical High Medium Low Info; do counts+="$s: ${c[$s]} &nbsp; "; done
    {
        cat <<HTML_HEAD
<!DOCTYPE html><html><head><meta charset="utf-8"><title>PrivEsc Audit - $(html_escape "$HOST")</title>
<style>
body{font-family:Segoe UI,Ubuntu,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}
h1{font-size:20px} .meta{color:#94a3b8;font-size:13px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #1e293b;padding:8px;text-align:left;vertical-align:top}
th{background:#1e293b;position:sticky;top:0}
.sev{padding:2px 8px;border-radius:4px;color:#fff;font-weight:600;font-size:12px}
pre{margin:0;white-space:pre-wrap;word-break:break-all;color:#cbd5e1;font-size:12px;max-width:520px;overflow:auto}
tr:nth-child(even){background:#111c33}
</style></head><body>
<h1>Linux Local Privilege-Escalation Audit</h1>
<div class="meta">Host: $(html_escape "$HOST") &nbsp;|&nbsp; User: $(html_escape "$ME") (uid $MY_UID) &nbsp;|&nbsp;
Generated: $(date '+%Y-%m-%d %H:%M:%S') &nbsp;|&nbsp; Depth: $DEPTH &nbsp;|&nbsp; Min severity: $MIN_SEV<br>
Counts &nbsp; $counts</div>
<table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Remediation</th><th>Evidence</th></tr></thead>
<tbody>
HTML_HEAD
        for i in "${ORDER[@]}"; do
            s=${F_SEV[$i]}
            printf '<tr>\n  <td><span class="sev" style="background:%s">%s</span></td>\n  <td>%s</td>\n  <td>%s</td>\n  <td>%s</td>\n  <td><pre>%s</pre></td>\n</tr>\n' \
                "${bg[$s]}" "$s" "$(html_escape "${F_CAT[$i]}")" "$(html_escape "${F_TITLE[$i]}")" \
                "$(html_escape "${F_REM[$i]}")" "$(html_escape "${F_EVID[$i]}")"
        done
        cat <<'HTML_TAIL'
</tbody></table>
<p class="meta">Read-only enumeration. Authorized assessment use only.</p>
</body></html>
HTML_TAIL
    } > "$path"
}
#endregion

#region ---------- Orchestration ----------
if has_format console; then
    printf '%sprivesc-audit.sh v%s - read-only Linux privesc audit (authorized use only)%s\n' "$C_CYAN" "$VERSION" "$C_RESET"
fi
check_system
check_users
check_sudo
check_suid
check_capabilities
check_services
check_cron
check_autoruns
check_path
check_containers
check_processes
check_hardening
check_defenses
check_credentials
check_writable_sweep
check_secret_scan
check_network
export_report
#endregion
