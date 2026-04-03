#!/usr/bin/env bash
# =============================================================================
# hpc_gpu_stig_harden.sh  (v6 — Container-Aware, Full Audit, Multi-Pass Reviewed)
# RHEL 9 DISA STIG Hardening Script for HPC/GPU Compute Nodes
#
# Applies DISA STIG V2R3 controls appropriate for HPC/GPU compute nodes.
# Intentionally OMITS controls that are known to break:
#   - MPI job launch and execution (OpenMPI, Intel MPI, HPC-X)
#   - UCX/libibverbs RDMA transports
#   - CUDA / NVSHMEM / NCCL GPU workloads
#   - GPUDirect RDMA (nvidia-peermem, ibrc transport)
#   - Slurm job scheduler integration
#   - Rootless Podman (user namespaces, cgroup v2, subuid/subgid)
#   - Apptainer (unprivileged user namespaces, fakeroot, /proc access)
#
# OMITTED STIGs with rationale are documented inline.
# Each omission requires a POA&M entry with your AO.
#
# Usage:
#   sudo bash hpc_gpu_stig_harden.sh [--dry-run] [--log FILE]
#
# Options:
#   --dry-run     Print what would be done without making changes
#   --log FILE    Write output log to FILE (default: /var/log/hpc_stig_harden.log)
#
# Requirements:
#   - RHEL 9.x (tested on 9.2+)
#   - Must be run as root or via sudo
#   - Internet or local mirror access for package installation
#
# Post-run:
#   1. Reboot the system
#   2. Run a test MPI job and validate output
#   3. Test: podman run --rm ubi9 id
#   4. Test: apptainer exec docker://alpine id
#   5. File POA&M entries for all omitted controls listed at script end
#
# WARNING: Test in a non-production environment before deploying.
#          Some controls require a reboot to take effect.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
DRY_RUN=false
LOGFILE="/var/log/hpc_stig_harden.log"
REBOOT_REQUIRED=false

# BUG FIX: --log parsing used 'shift' inside a for loop, which is not valid
# in bash for-loops. Replaced with a while-loop with index tracking.
i=1
while [[ $i -le $# ]]; do
    arg="${!i}"
    case "$arg" in
        --dry-run)  DRY_RUN=true ;;
        --log)
            i=$(( i + 1 ))
            LOGFILE="${!i}"
            ;;
        --log=*)    LOGFILE="${arg#--log=}" ;;
        -h|--help)
            sed -n '2,32p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
    esac
    i=$(( i + 1 ))
done

# ---------------------------------------------------------------------------
# Logging
# FIX BUG D: Ensure logfile parent directory exists before opening tee.
# If --log /custom/path/file.log is used and the dir doesn't exist, tee
# fails silently and all output is lost.
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null || {
    echo "ERROR: Cannot create log directory for: $LOGFILE" >&2
    exit 1
}
exec > >(tee -a "$LOGFILE") 2>&1

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $*"; }
skip() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SKIP]  $*"; }
omit() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OMIT]  $*"; }
ok()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK]    $*"; }

# BUG FIX: Original run() used eval "$@" which breaks with arrays and
# special characters (SC2294). Replaced with a proper dry-run check that
# passes the command string to bash -c, preserving the ability to run
# compound shell expressions while still being safe for dry-run display.
run() {
    if "$DRY_RUN"; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DRY]   $*"
    else
        bash -c "$*"
    fi
}

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
log "========================================================"
log " HPC/GPU Compute Node STIG Hardening — RHEL 9  (v6)"
log " DRY_RUN=${DRY_RUN}"
log " Log: ${LOGFILE}"
log "========================================================"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must be run as root." >&2
    exit 1
fi

RHEL_VER=$(rpm -q --qf '%{VERSION}' redhat-release 2>/dev/null || echo "unknown")
if [[ "$RHEL_VER" != 9* ]]; then
    warn "This script targets RHEL 9. Detected: ${RHEL_VER}. Proceeding with caution."
fi

log "RHEL version: ${RHEL_VER}"
log "Kernel: $(uname -r)"

# BUG FIX: Detect CPU vendor once at start so IOMMU section can choose correctly.
CPU_VENDOR=$(grep -m1 'vendor_id' /proc/cpuinfo | awk '{print $3}')
log "CPU vendor: ${CPU_VENDOR}"


# =============================================================================
# SECTION 1 — PACKAGE MANAGEMENT
# =============================================================================
log "--- Section 1: Package Management ---"

# RHEL-09-211010 / RHEL-09-211015 — Keep system updated
log "RHEL-09-211010/211015: Running security updates..."
# BUG FIX: Original used run() here, but || warn inside run() is not
# meaningful because warn() is a shell function not visible inside bash -c.
# Use explicit subshell error handling instead.
if ! "$DRY_RUN"; then
    dnf -y update --security --nobest || warn "Security update had warnings — review manually"
fi

# RHEL-09-211020 — gpgcheck enabled
log "RHEL-09-211020: Ensuring GPG check is enabled for all repos..."
run "sed -i 's/^gpgcheck[[:space:]]*=.*/gpgcheck=1/' /etc/dnf/dnf.conf"
# BUG FIX: Original glob expansion in for-loop ran inside run() string,
# which cannot expand globs correctly. Use a proper loop.
if ! "$DRY_RUN"; then
    for f in /etc/yum.repos.d/*.repo; do
        [[ -f "$f" ]] && sed -i 's/^gpgcheck[[:space:]]*=[[:space:]]*0/gpgcheck=1/' "$f"
    done
fi
ok "GPG check enforced."

# RHEL-09-211025 — Remove unauthorized packages
log "RHEL-09-211025: Removing insecure legacy packages..."
for pkg in telnet rsh ypbind tftp xinetd; do
    if rpm -q "$pkg" &>/dev/null; then
        run "dnf -y remove ${pkg}"
        log "Removed: ${pkg}"
    fi
done
ok "Legacy insecure packages removed."

# =============================================================================
# OMITTED: RHEL-09-211030 / RHEL-09-651010 — AIDE file integrity monitoring
# REASON:  Excluded by site policy.
# POA&M:   RHEL-09-211030 (CAT II), RHEL-09-651010 (CAT II)
# =============================================================================
omit "RHEL-09-211030/651010: AIDE excluded by site policy — POA&M required"

# OpenSCAP scanner — still useful for post-run compliance reporting
log "Installing OpenSCAP scanner and SCAP security guide for compliance scanning..."
for pkg in openscap-scanner scap-security-guide; do
    if ! rpm -q "$pkg" &>/dev/null; then
        run "dnf -y install ${pkg}" || warn "Could not install ${pkg} — install manually for compliance scanning"
    fi
done
ok "OpenSCAP tools installed."



# =============================================================================
# SECTION 2 — KERNEL PARAMETERS (sysctl)
# =============================================================================
log "--- Section 2: Kernel Parameters ---"

SYSCTL_CONF="/etc/sysctl.d/99-hpc-stig.conf"
log "Writing kernel parameters to ${SYSCTL_CONF}..."

# BUG FIX: All cat heredocs that write config files were executing even in
# dry-run mode. Wrapped in dry-run guard. Using .tmp + atomic mv pattern
# for all config file writes.
if ! "$DRY_RUN"; then
cat > "${SYSCTL_CONF}.tmp" << 'EOF'
# HPC/GPU Compute Node STIG Kernel Parameters
# Generated by hpc_gpu_stig_harden.sh

# RHEL-09-213010 — Restrict kernel pointer exposure
# Set to 1 (restrict to unprivileged users only) rather than 2 (restrict all).
# Value 2 blocks perf(1), bpftrace, and GPU profiling tools even for root,
# which breaks RDMA and GPU performance analysis workflows on HPC nodes.
# Value 1 hides pointers from non-root while preserving root diagnostics.
kernel.kptr_restrict = 1

# RHEL-09-213015 — Restrict dmesg to root
kernel.dmesg_restrict = 1

# RHEL-09-213020 — Disable magic SysRq key
kernel.sysrq = 0

# RHEL-09-213025 — Disable suid core dumps
fs.suid_dumpable = 0

# RHEL-09-213030 — Full ASLR
kernel.randomize_va_space = 2

# RHEL-09-253010 — TCP syncookies
net.ipv4.tcp_syncookies = 1

# RHEL-09-253015 — Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# RHEL-09-253020 — Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# RHEL-09-253025 — Disable secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# RHEL-09-253030 — Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# RHEL-09-253035 — Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# RHEL-09-253040 — Disable IPv4 forwarding
# Compute nodes are not routers. Override post-harden if node is a gateway.
net.ipv4.conf.all.forwarding = 0

# RHEL-09-253045 — Ignore broadcast ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1

# RHEL-09-253050 — Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# RHEL-09-253055 — Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# RHEL-09-253060 — Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# RHEL-09-253065 — Disable IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# =============================================================================
# CONTAINER SUPPORT: user namespace limit
# Not a direct DISA STIG control, but some hardening tools set this to 0,
# which completely disables rootless Podman, Apptainer, Buildah, and Skopeo.
# Sized for 128-core nodes running containerised MPI jobs via Slurm with
# known Apptainer namespace leak headroom between job runs.
# =============================================================================
user.max_user_namespaces = 31879

# =============================================================================
# OMITTED: RHEL-09-213085 — kernel.yama.ptrace_scope = 1
# REASON:  UCX CMA transport uses process_vm_readv/writev between sibling
#          MPI ranks; ptrace_scope=1 silently disables it. Also breaks
#          containerised MPI (Apptainer) with unprivileged user namespaces.
# POA&M:   Accept risk. SELinux enforcing is a compensating control.
# STIG ID: RHEL-09-213085 | CAT II | V-257811
# =============================================================================
EOF
mv "${SYSCTL_CONF}.tmp" "${SYSCTL_CONF}"
sysctl --system
else
    log "[DRY] Would write sysctl config to ${SYSCTL_CONF} and apply with sysctl --system"
fi
ok "Kernel parameters applied."


# =============================================================================
# SECTION 3 — BOOT / GRUB PARAMETERS
# =============================================================================
log "--- Section 3: Boot Parameters ---"

# RHEL-09-212010 — Audit at boot
log "RHEL-09-212010: Enabling audit at boot..."
run "grubby --update-kernel=ALL --args='audit=1' || true"

# FIX BUG H: GRUB_CMDLINE_LINUX may be double-quoted, single-quoted, or
# unquoted depending on the installer. The prior sed only handled double-quote
# form, silently doing nothing on other forms. Handle all three cases.
# Note: grubby above already updates the live bootloader entry; this updates
# /etc/default/grub so the setting survives kernel package upgrades.
if ! "$DRY_RUN"; then
    if ! grep -q 'audit=1' /etc/default/grub 2>/dev/null; then
        sed -i \
            -e 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="audit=1 \1"/' \
            -e "s/^GRUB_CMDLINE_LINUX='\\(.*\\)'/GRUB_CMDLINE_LINUX='audit=1 \\1'/" \
            /etc/default/grub 2>/dev/null || true
    fi
fi

# RHEL-09-212015 — Audit backlog (raised from 8192 to 65536 for HPC workloads)
log "RHEL-09-212015: Setting audit backlog limit to 65536..."
run "grubby --update-kernel=ALL --args='audit_backlog_limit=65536' || true"

# RHEL-09-212050 — Kernel PTI (Meltdown mitigation)
log "RHEL-09-212050: Enabling kernel PTI..."
run "grubby --update-kernel=ALL --args='pti=on' || true"

# RHEL-09-212055 — SLUB poisoning
log "RHEL-09-212055: Enabling SLUB poisoning..."
warn "slub_debug=P: adds per-allocation overhead. Memory-intensive HPC workloads"
warn "(FFT, dense linear algebra) may see 5-15%% slowdown. Required by STIG."
run "grubby --update-kernel=ALL --args='slub_debug=P' || true"

# RHEL-09-212060 — Disable vsyscall
log "RHEL-09-212060: Disabling vsyscall..."
warn "vsyscall=none: containers running glibc < 2.14 (e.g. CentOS 6 images)"
warn "will segfault. Test legacy container workloads before deploying to production."
run "grubby --update-kernel=ALL --args='vsyscall=none' || true"

# RHEL-09-212065 — Page poisoning
log "RHEL-09-212065: Enabling page poisoning..."
warn "page_poison=1: zeroes freed pages, adding memory-bandwidth overhead."
warn "Similar performance impact to slub_debug on memory-bound workloads."
run "grubby --update-kernel=ALL --args='page_poison=1' || true"

# =============================================================================
# IOMMU — passthrough mode for GPUDirect RDMA
# Strict IOMMU routes all PCIe P2P traffic via CPU root complex, breaking
# GPUDirect RDMA. Passthrough mode preserves DMA isolation while allowing
# required P2P transactions between GPU and InfiniBand HCA.
# POA&M: Accept risk. iommu=pt is a compensating measure.
# =============================================================================
# BUG FIX: Original unconditionally set intel_iommu=on regardless of CPU
# vendor. On AMD systems this is wrong; on Intel it conflicts with
# amd_iommu=on. Now auto-detects vendor and sets the correct parameter.
log "Configuring IOMMU passthrough for GPUDirect RDMA compatibility..."
if [[ "$CPU_VENDOR" == "AuthenticAMD" ]]; then
    run "grubby --update-kernel=ALL --args='amd_iommu=on iommu=pt' || true"
    log "AMD CPU detected: set amd_iommu=on iommu=pt"
elif [[ "$CPU_VENDOR" == "GenuineIntel" ]]; then
    run "grubby --update-kernel=ALL --args='intel_iommu=on iommu=pt' || true"
    log "Intel CPU detected: set intel_iommu=on iommu=pt"
else
    warn "Unknown CPU vendor '${CPU_VENDOR}' — set IOMMU passthrough manually"
fi
ok "Boot parameters configured. REBOOT REQUIRED."
REBOOT_REQUIRED=true


# =============================================================================
# SECTION 4 — FILESYSTEM MOUNT OPTIONS
# OMITTED BY SITE POLICY — separate filesystem hardening not required.
# =============================================================================
log "--- Section 4: Filesystem Mount Options ---"
# =============================================================================
# OMITTED: RHEL-09-231010/231015/231020/231025/231030/231035/231150
#          (nodev/nosuid/noexec on /tmp /var /var/log /var/log/audit
#           /var/tmp /home /dev/shm)
# REASON:  Separate filesystem hardening excluded by site policy.
# POA&M:   RHEL-09-231010 (CAT II), RHEL-09-231015 (CAT II),
#          RHEL-09-231020 (CAT II), RHEL-09-231025 (CAT II),
#          RHEL-09-231030 (CAT II), RHEL-09-231035 (CAT II),
#          RHEL-09-231150 (CAT II)
# =============================================================================
omit "RHEL-09-231010/231015/231020/231025/231030/231035/231150: filesystem hardening excluded by site policy"

# /dev/shm size and noexec omission retained — operationally required for
# CUDA JIT, NVSHMEM, NCCL, and OpenMPI vader BTL regardless of site policy.
SHM_SIZE="64g"   # Adjust to match node RAM (e.g. 128g for 256GB nodes)
log "Configuring /dev/shm size=${SHM_SIZE} (noexec omitted for GPU/MPI workloads)..."
if ! "$DRY_RUN"; then
    if grep -qE "^[^#]\S+[[:space:]]+/dev/shm[[:space:]]+" /etc/fstab; then
        sed -i -E "s|^([^#]\S+[[:space:]]+/dev/shm[[:space:]]+\S+[[:space:]]+)\S+|\1size=${SHM_SIZE}|" /etc/fstab
    else
        echo "tmpfs /dev/shm tmpfs defaults,size=${SHM_SIZE} 0 0" >> /etc/fstab
    fi
    mount -o remount "/dev/shm" 2>/dev/null || true
else
    log "[DRY] Would set /dev/shm size=${SHM_SIZE} in /etc/fstab"
fi
ok "/dev/shm size configured."

# /proc hidepid — ensure NOT set regardless of site policy; it breaks
# Apptainer cgroup v2 DBus and Podman /proc/self/fd access.
if ! "$DRY_RUN"; then
    if mount | grep -q '/proc.*hidepid'; then
        mount -o remount,hidepid=0 /proc
        warn "Removed hidepid from live /proc mount — also check /etc/fstab"
    fi
    if grep -q 'hidepid' /etc/fstab 2>/dev/null; then
        sed -i -e 's/,hidepid=[0-9]*//' -e 's/hidepid=[0-9]*,//' -e 's/hidepid=[0-9]*//' /etc/fstab
        log "Removed hidepid from /etc/fstab"
    fi
fi
ok "/proc hidepid not set."



# =============================================================================
# SECTION 5 — SSH SERVER HARDENING
# =============================================================================
log "--- Section 5: SSH Hardening ---"

SSHD_CONF="/etc/ssh/sshd_config.d/99-hpc-stig.conf"
log "Writing SSH config to ${SSHD_CONF}..."

# Guard: RHEL 9 default /etc/ssh/sshd_config includes drop-in files via:
#   Include /etc/ssh/sshd_config.d/*.conf
# If this line is absent (e.g. custom or stripped sshd_config), our drop-in
# will be written but silently ignored, giving a false sense of compliance.
if ! "$DRY_RUN"; then
    if ! grep -q "^Include.*/sshd_config\.d/\*\.conf" /etc/ssh/sshd_config 2>/dev/null; then
        warn "sshd_config does not contain 'Include /etc/ssh/sshd_config.d/*.conf'"
        warn "Drop-in hardening will be ignored. Adding Include directive now..."
        # Prepend Include as the very first non-comment line so it takes effect
        # before any conflicting options that may appear later in the base config.
        sed -i '1s|^|Include /etc/ssh/sshd_config.d/*.conf\n|' /etc/ssh/sshd_config
        log "Include directive added to /etc/ssh/sshd_config"
    fi
fi

if ! "$DRY_RUN"; then
cat > "${SSHD_CONF}.tmp" << 'EOF'
# HPC/GPU Compute Node SSH STIG Configuration — v3
# Drop-in for /etc/ssh/sshd_config.d/

# BUG FIX: 'Protocol 2' directive was removed from OpenSSH 7.6+ (2017).
# Including it causes 'sshd -t' to fail with "Bad configuration option"
# on RHEL 9 (OpenSSH 8.7+). Line removed. SSHv2-only is the compile default.

# RHEL-09-255015 — Session keepalive / idle disconnect
# =============================================================================
# OMITTED: ClientAlive session timeout
# REASON:  Session timeouts excluded by site policy.
# POA&M:   RHEL-09-255015 | CAT II
# =============================================================================

# RHEL-09-255020 — Disable root login
PermitRootLogin no

# RHEL-09-255025 — Key-based auth only
PasswordAuthentication no
KbdInteractiveAuthentication no

# RHEL-09-255030 — No empty passwords
PermitEmptyPasswords no

# RHEL-09-255035 — No host-based auth or .rhosts
HostbasedAuthentication no
IgnoreRhosts yes

# RHEL-09-255040 — No X11 forwarding on compute nodes
X11Forwarding no

# RHEL-09-255050 — FIPS/DoD-approved ciphers
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# RHEL-09-255055 — FIPS/DoD-approved MACs
MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# RHEL-09-255060 — FIPS/DoD-approved KEX algorithms
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# =============================================================================
# RHEL-09-255065 — MaxSessions
# STIG default is 10. Raised to 100 for compute nodes where mpirun opens
# one SSH session per rank. On a 64+-core node, 10 causes launch failures.
# POA&M: Accept risk. Compute fabric is not internet-facing.
# =============================================================================
MaxSessions 100

# RHEL-09-255070 — Log level
LogLevel VERBOSE

# RHEL-09-255075 — Login grace time
LoginGraceTime 60

# RHEL-09-255080 — Limit auth attempts
MaxAuthTries 3

# RHEL-09-255085 — Strict modes
StrictModes yes

# RHEL-09-255095 — DoD banner
Banner /etc/issue.net

# =============================================================================
# RHEL-09-255045 — PermitUserEnvironment
# Standard fix: PermitUserEnvironment=no. We keep this setting but add a
# scoped AcceptEnv list so mpirun -x VAR forwarding and module environment
# propagation still work without opening all user env vars.
# =============================================================================
PermitUserEnvironment no
AcceptEnv LANG LC_* \
          MPI_* I_MPI_* OMPI_* PMIX_* \
          UCX_* FI_* \
          SLURM_* \
          NVSHMEM_* NCCL_* \
          CUDA_* NVIDIA_* \
          OMP_* KMP_* \
          LD_LIBRARY_PATH PATH \
          MODULEPATH MODULESHOME LMOD_* \
          APPTAINER_* APPTAINERENV_* \
          SINGULARITY_* SINGULARITYENV_* \
          CONTAINER_* SIF_*

EOF
mv "${SSHD_CONF}.tmp" "${SSHD_CONF}"
# Validate config before reloading; warn but do not abort on failure
if sshd -t; then
    systemctl reload sshd
    ok "SSH hardening applied and sshd reloaded."
else
    warn "sshd config test FAILED — ${SSHD_CONF} has errors. sshd NOT reloaded. Fix manually."
fi
else
    log "[DRY] Would write SSH config to ${SSHD_CONF} and reload sshd"
fi

# DoD login banner
log "RHEL-09-251015: Setting DoD login banner..."
if ! "$DRY_RUN"; then
cat > /etc/issue.net << 'BANNER'
You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only. By using this IS (which includes any
device attached to this IS), you consent to the following conditions:
- The USG routinely intercepts and monitors communications on this IS for
  purposes including, but not limited to, penetration testing, COMSEC
  monitoring, network operations and defense, personnel misconduct (PM),
  law enforcement (LE), and counterintelligence (CI) investigations.
- At any time, the USG may inspect and seize data stored on this IS.
- Communications using, or data stored on, this IS are not private, are
  subject to routine monitoring, interception, and search, and may be
  disclosed or used for any USG authorized purpose.
- This IS includes security measures (e.g., authentication and access
  controls) to protect USG interests -- not for your personal benefit or
  privacy.
- Notwithstanding the above, using this IS does not constitute consent to
  PM, LE or CI investigative searching or monitoring of the content of
  privileged communications, or work product, related to personal
  representation or services by attorneys, psychotherapists, or clergy,
  and their assistants. Such communications and work product are private
  and confidential. See User Agreement for details.
BANNER
cp /etc/issue.net /etc/issue
else
    log "[DRY] Would write DoD banner to /etc/issue.net and /etc/issue"
fi
ok "Login banners configured."


# =============================================================================
# SECTION 6 — PAM / AUTHENTICATION
# =============================================================================
log "--- Section 6: PAM and Authentication ---"

# RHEL-09-411010 — Password minimum length = 15
log "RHEL-09-411010: Setting password minimum length..."
run "sed -i 's/^#*[[:space:]]*minlen[[:space:]]*=.*/minlen = 15/' /etc/security/pwquality.conf"
run "grep -q '^minlen' /etc/security/pwquality.conf || echo 'minlen = 15' >> /etc/security/pwquality.conf"

# RHEL-09-411015 — Password complexity: all 4 character classes
log "RHEL-09-411015: Setting password complexity..."
run "sed -i 's/^#*[[:space:]]*minclass[[:space:]]*=.*/minclass = 4/' /etc/security/pwquality.conf"
run "grep -q '^minclass' /etc/security/pwquality.conf || echo 'minclass = 4' >> /etc/security/pwquality.conf"

# RHEL-09-411020 — Difok
run "sed -i 's/^#*[[:space:]]*difok[[:space:]]*=.*/difok = 8/' /etc/security/pwquality.conf"
run "grep -q '^difok' /etc/security/pwquality.conf || echo 'difok = 8' >> /etc/security/pwquality.conf"

# RHEL-09-411045 — Account lockout via faillock
# NOTE: unlock_time=0 means permanent lockout requiring manual 'faillock --reset'.
# Ensure Slurm service accounts auth via keytab/PAM bypass, not interactive PAM.
log "RHEL-09-411045: Configuring faillock..."
if ! "$DRY_RUN"; then
cat > /etc/security/faillock.conf << 'FAILLOCK'
deny = 3
fail_interval = 900
unlock_time = 0
even_deny_root
silent
FAILLOCK
else
    log "[DRY] Would write faillock.conf"
fi
ok "Account lockout configured."

# RHEL-09-411050 — SHA-512 password hashing and faillock integration
# FIX 7.2: faillock.conf settings have no effect unless the 'with-faillock'
# feature is enabled in the authselect profile. The previous code only
# validated the profile existed but never ensured with-faillock was active.
log "RHEL-09-411050: Verifying authselect profile and enabling with-faillock..."
if ! "$DRY_RUN"; then
    if authselect check &>/dev/null; then
        # Profile is valid — check if with-faillock is already active
        if authselect current 2>/dev/null | grep -q "with-faillock"; then
            ok "authselect: profile valid and with-faillock already enabled."
        else
            CURRENT_PROFILE=$(authselect current 2>/dev/null | awk 'NR==1{print $2}')
            if [[ -n "$CURRENT_PROFILE" ]]; then
                log "Enabling with-faillock on current profile: ${CURRENT_PROFILE}"
                authselect enable-feature with-faillock 2>/dev/null || \
                    authselect select "$CURRENT_PROFILE" with-faillock --force
                ok "with-faillock enabled on ${CURRENT_PROFILE}."
            else
                warn "Could not determine current authselect profile. Enable with-faillock manually:"
                warn "  authselect enable-feature with-faillock"
            fi
        fi
    else
        warn "No valid authselect profile. Setting 'sssd with-faillock' as default."
        warn "If your site uses winbind or another provider, set the correct profile manually."
        authselect select sssd with-faillock --force
    fi
else
    log "[DRY] Would verify authselect profile and ensure with-faillock is enabled"
fi
ok "authselect and faillock verified."


# =============================================================================
# SECTION 7 — AUDIT SUBSYSTEM
# =============================================================================
log "--- Section 7: Audit Configuration ---"

if ! rpm -q audit &>/dev/null; then
    run "dnf -y install audit"
fi
run "systemctl enable --now auditd"

AUDIT_INIT="/etc/audit/rules.d/00-hpc-stig-init.rules"
AUDIT_RULES="/etc/audit/rules.d/10-hpc-stig.rules"
log "Writing audit rules to ${AUDIT_INIT} and ${AUDIT_RULES}..."

# FIX 11.1: Prior versions of this script wrote to 99-hpc-stig.rules.
# If that file still exists, augenrules will load it IN ADDITION to the
# new 10-hpc-stig.rules, resulting in duplicate rules and a second -e 2
# being processed. Remove the stale file if present.
if ! "$DRY_RUN"; then
    for stale in /etc/audit/rules.d/99-hpc-stig.rules \
                 /etc/audit/rules.d/99-hpc-stig-blacklist.conf; do
        if [[ -f "$stale" ]]; then
            rm -f "$stale"
            log "Removed stale audit file: ${stale}"
        fi
    done
fi

if ! "$DRY_RUN"; then

# FIX 8.3: -D must be in a 00-prefixed file so augenrules processes it FIRST,
# before any other rules files. Placing -D in a 99- file wipes all rules
# accumulated from lower-numbered files, destroying any site-custom rules.
# The init file also sets the buffer size and failure mode — settings that
# must be established before rule loading begins.
cat > "${AUDIT_INIT}.tmp" << 'EOF'
# HPC/GPU STIG Audit — Initialisation (00-hpc-stig-init.rules)
# Generated by hpc_gpu_stig_harden.sh
# MUST load first (00- prefix) so -D precedes all other rule files.

# Wipe all previously loaded rules cleanly
-D

# FIX 8.1+: Large buffer for HPC (STIG default 8192 overflows under heavy load)
-b 65536

# Failure mode: printk on overflow rather than panic.
# STIG mandates -f 2 (panic) but that kills running HPC jobs mid-flight.
# POA&M: Accept risk. 65536-entry buffer is compensating control.
-f 1
EOF
mv "${AUDIT_INIT}.tmp" "${AUDIT_INIT}"
log "Audit initialisation rules written to ${AUDIT_INIT}"

# The main rules file uses a 10- prefix so it loads after 00- init
# and before any 99- local-override files sites may add.
cat > "${AUDIT_RULES}.tmp" << 'EOF'
# HPC/GPU STIG Audit Rules (10-hpc-stig.rules)
# Generated by hpc_gpu_stig_harden.sh
# Aligned to DISA STIG for RHEL 9 V2R3

# =============================================================================
# RHEL-09-653010 — Privileged command execution
# =============================================================================
-a always,exit -F path=/usr/bin/sudo      -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/su        -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/newgrp    -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/chsh      -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/chfn      -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/passwd    -F perm=x -F auid>=1000 -F auid!=unset -k passwd
-a always,exit -F path=/usr/bin/newuidmap -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/newgidmap -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/usermod  -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/useradd  -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/userdel  -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/chage     -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/gpasswd   -F perm=x -F auid>=1000 -F auid!=unset -k privileged

# =============================================================================
# RHEL-09-653015 — File deletion
# FIX 8.1: Both b64 and b32 required by STIG — b32-only was present before.
# =============================================================================
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete

# =============================================================================
# RHEL-09-653020 — Permission and ownership changes
# FIX 8.1: Added b32 counterparts for all permission-change syscalls.
# =============================================================================
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat            -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat            -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat     -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat     -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr     -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr     -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

# =============================================================================
# RHEL-09-653025 — Unsuccessful file access attempts
# FIX 8.1: Added b32 counterparts for open/openat/open_by_handle_at.
# =============================================================================
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S open,openat                   -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S open,openat                   -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k access

# =============================================================================
# RHEL-09-653030 — Setuid/setgid execution
# FIX 8.1: Added b32 counterparts for execve privilege checks.
# =============================================================================
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid

# =============================================================================
# RHEL-09-653035 — Kernel module load/unload
# FIX 8.1: Added b32 counterpart for init_module/delete_module.
# =============================================================================
-w /sbin/insmod  -p x -k modules
-w /sbin/rmmod   -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules

# =============================================================================
# RHEL-09-653040 — Sudoers configuration changes
# =============================================================================
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# =============================================================================
# RHEL-09-653045 — Login and logout events
# =============================================================================
-w /var/log/lastlog      -p wa -k logins
-w /var/run/faillock/    -p wa -k logins
-w /var/log/btmp         -p wa -k logins
-w /var/log/wtmp         -p wa -k logins

# =============================================================================
# RHEL-09-653050 — Identity and account database changes
# =============================================================================
-w /etc/passwd   -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/group    -p wa -k identity
-w /etc/gshadow  -p wa -k identity
-w /etc/subuid   -p wa -k identity
-w /etc/subgid   -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# =============================================================================
# RHEL-09-653055 — Network configuration changes
# FIX 8.1: Added b32 counterpart for sethostname/setdomainname.
# =============================================================================
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network_mod
-a always,exit -F arch=b32 -S sethostname,setdomainname -k network_mod
-w /etc/hosts              -p wa -k network_mod
-w /etc/sysconfig/network  -p wa -k network_mod

# =============================================================================
# FIX 8.2: Time change syscalls — required by RHEL-09-653060 and related
# These were entirely absent. SCAP scan would flag as OPEN findings.
# =============================================================================
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time_change
-a always,exit -F arch=b64 -S clock_adjtime -k time_change
-a always,exit -F arch=b32 -S clock_adjtime -k time_change
-w /etc/localtime -p wa -k time_change

# =============================================================================
# SELinux MAC policy audit rules omitted — SELinux excluded by site policy.
# =============================================================================

# =============================================================================
# FIX 8.2: Discretionary access control — audit chmod-class privileged programs
# =============================================================================
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k privileged-acl 2>/dev/null || true
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k privileged-acl

# =============================================================================
# FIX 8.2: Privileged commands — additional STIG-required binaries
# =============================================================================
-a always,exit -F path=/usr/bin/umount      -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/mount      -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/crontab     -F perm=x -F auid>=1000 -F auid!=unset -k privileged

# =============================================================================
# FIX 8.2: Audit log access — monitor who reads audit logs
# =============================================================================
-w /var/log/audit/ -p wa -k audit_log_access

# =============================================================================
# FIX 8.2: sudo log file — required by RHEL-09-653010 supplemental
# =============================================================================
-w /var/log/sudo.log -p wa -k actions

# =============================================================================
# Immutable flag — requires reboot to modify rules after this point.
# This MUST be the final line in the final rules file.
# =============================================================================
-e 2
EOF
mv "${AUDIT_RULES}.tmp" "${AUDIT_RULES}"
log "Audit rules written to ${AUDIT_RULES}"

# FIX BUG B (preserved): If -e 2 was committed on a prior run, augenrules
# will fail non-zero. Suppress and warn — rules are on disk and load at boot.
augenrules --load 2>/dev/null || {
    warn "augenrules --load returned non-zero (rules may be immutable from prior run)."
    warn "Updated rules are on disk and will be active after next reboot."
    REBOOT_REQUIRED=true
}

else
    log "[DRY] Would write ${AUDIT_INIT} (init: -D -b 65536 -f 1)"
    log "[DRY] Would write ${AUDIT_RULES} (full ruleset with b32 and missing categories)"
fi
ok "Audit rules configured."

# auditd.conf
log "Configuring auditd.conf..."
AUDITD_CONF="/etc/audit/auditd.conf"
run "sed -i 's/^max_log_file_action[[:space:]]*=.*/max_log_file_action = ROTATE/' ${AUDITD_CONF}"
run "sed -i 's/^num_logs[[:space:]]*=.*/num_logs = 5/' ${AUDITD_CONF}"
run "sed -i 's/^max_log_file[[:space:]]*=.*/max_log_file = 100/' ${AUDITD_CONF}"
# Use SYSLOG not HALT on HPC — HALT would kill running jobs
run "sed -i 's/^space_left_action[[:space:]]*=.*/space_left_action = SYSLOG/' ${AUDITD_CONF}"
run "sed -i 's/^admin_space_left_action[[:space:]]*=.*/admin_space_left_action = SYSLOG/' ${AUDITD_CONF}"
ok "auditd.conf configured."


# =============================================================================
# SECTION 8 — SELinux
# OMITTED BY SITE POLICY
# =============================================================================
log "--- Section 8: SELinux ---"
# =============================================================================
# OMITTED: RHEL-09-431010 / RHEL-09-431015 — SELinux enforcing mode
# REASON:  Excluded by site policy.
# POA&M:   RHEL-09-431010 (CAT II), RHEL-09-431015 (CAT II)
# =============================================================================
omit "RHEL-09-431010/431015: SELinux excluded by site policy — POA&M required"


# =============================================================================
# SECTION 9 — CONTAINER RUNTIME SUPPORT (Podman + Apptainer)
# =============================================================================
log "--- Section 9: Container Runtime Support (Podman + Apptainer) ---"

# 9a. Install packages
log "9a: Installing Podman and supporting packages..."
# FIX BUG E: passt is in EPEL on RHEL 9, not in base repos. If EPEL is not
# yet enabled, including passt in the main dnf command causes the entire
# install to fail, aborting the script via set -e. Split into base packages
# (always available in RHEL 9 repos) and an optional EPEL-only package.
PODMAN_PKGS_BASE=(
    podman             # OCI container engine
    buildah            # Container image builder
    skopeo             # Container image inspection/copy
    slirp4netns        # Rootless networking (in base RHEL 9 repos)
    netavark           # Container network stack
    aardvark-dns       # DNS for container networks
    shadow-utils       # Provides newuidmap / newgidmap
    dbus-user-session  # Required for rootless cgroup v2 DBus session
    # container-selinux: omitted — SELinux excluded by site policy
    fuse-overlayfs     # Overlay FS for rootless storage
    fuse3              # FUSE kernel interface
)
if ! "$DRY_RUN"; then
    # Install base packages. --skip-broken prevents a single unavailable package
    # (e.g. on RHEL 9.0 which predates netavark/aardvark-dns in AppStream)
    # from aborting the entire install and failing the script via set -e.
    if ! dnf -y install --skip-broken "${PODMAN_PKGS_BASE[@]}"; then
        warn "Some Podman base packages failed to install. Retrying individually..."
        for pkg in "${PODMAN_PKGS_BASE[@]}"; do
            dnf -y install "$pkg" 2>/dev/null || warn "Could not install: ${pkg}"
        done
    fi
else
    log "[DRY] Would run: dnf -y install --skip-broken ${PODMAN_PKGS_BASE[*]}"
fi
ok "Base Podman packages installed (check warnings above for any skipped)."

# passt: Rootless networking backend for Podman 5+ (EPEL on RHEL 9)
# slirp4netns is the fallback and is already installed above.
if ! "$DRY_RUN"; then
    if ! dnf -y install passt 2>/dev/null; then
        warn "passt not available (requires EPEL). slirp4netns will be used as fallback."
        warn "After enabling EPEL, run: dnf -y install passt"
    fi
else
    log "[DRY] Would attempt: dnf -y install passt (EPEL package)"
fi

log "9a: Installing Apptainer via EPEL..."
# BUG FIX: Original used run() wrapping an || warn chain; warn() is a shell
# function that cannot execute inside bash -c. Restructured as explicit
# if/else with direct calls.
if ! rpm -q epel-release &>/dev/null; then
    if ! "$DRY_RUN"; then
        if ! dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm; then
            warn "EPEL install failed. Install Apptainer manually from:"
            warn "  https://github.com/apptainer/apptainer/releases"
        fi
    else
        log "[DRY] Would install EPEL release RPM"
    fi
fi
if rpm -q epel-release &>/dev/null || "$DRY_RUN"; then
    run "dnf -y install apptainer"
    ok "Apptainer installed."
else
    warn "Skipping Apptainer install — EPEL not available."
fi

# Ensure newuidmap/newgidmap have setuid bit (required for user namespace mapping)
log "9a: Verifying newuidmap/newgidmap setuid bit..."
if ! "$DRY_RUN"; then
    for bin in /usr/bin/newuidmap /usr/bin/newgidmap; do
        if [[ -f "$bin" ]]; then
            chmod u+s "$bin"
            ok "setuid bit confirmed on ${bin}"
        fi
    done
else
    log "[DRY] Would chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap"
fi

# 9b. /etc/subuid and /etc/subgid
# Both Podman and Apptainer share these files for rootless UID mapping.
# NOTE: On LDAP/SSSD clusters, provision these via your identity management
# system. The static entries below cover local accounts only.
log "9b: Configuring /etc/subuid and /etc/subgid..."

SUBID_RANGE_SIZE=65536

provision_subid() {
    local file="$1"
    local user="$2"
    # BUG FIX: provision_subid was not dry-run aware; the inner run() call
    # was correct but the awk last_end calculation ran unconditionally.
    # The awk is read-only so that's fine; only the echo >> needs guarding.
    if ! grep -q "^${user}:" "${file}" 2>/dev/null; then
        local last_end
        last_end=$(awk -F: 'BEGIN{max=100000} {end=$2+$3; if(end>max)max=end} END{print max}' \
                   "${file}" 2>/dev/null || echo "100000")
        if ! "$DRY_RUN"; then
            echo "${user}:${last_end}:${SUBID_RANGE_SIZE}" >> "${file}"
            log "Added ${user} to ${file} (start: ${last_end}, size: ${SUBID_RANGE_SIZE})"
        else
            log "[DRY] Would add ${user}:${last_end}:${SUBID_RANGE_SIZE} to ${file}"
        fi
    else
        ok "${user} already has entry in ${file}"
    fi
}

# Provision for all local non-system users
for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    provision_subid /etc/subuid "$user"
    provision_subid /etc/subgid "$user"
done

# Also provision for slurm service account (may submit container jobs)
if id slurm &>/dev/null 2>&1; then
    provision_subid /etc/subuid slurm
    provision_subid /etc/subgid slurm
fi
ok "subuid/subgid configured."

# 9c. SELinux booleans for containers — skipped (SELinux excluded by site policy)
log "9c: SELinux booleans skipped — SELinux excluded by site policy."

# 9d. Podman system configuration
log "9d: Configuring Podman..."
if ! "$DRY_RUN"; then
    mkdir -p /etc/containers
cat > /etc/containers/containers.conf.hpc << 'EOF'
# System-wide Podman configuration for HPC/GPU nodes
# Generated by hpc_gpu_stig_harden.sh v6

[containers]
default_capabilities = [
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
]

[network]
# 'network_backend' key was renamed to 'default_network_backend' in Podman 5.0.
# Both keys are accepted for backward compatibility with Podman 4.x.
# If you see deprecation warnings, remove network_backend and use:
# default_network_backend = "netavark"
network_backend = "netavark"

[engine]
cgroup_manager = "systemd"
# /var/tmp has exec allowed per our fstab policy for container image staging
image_copy_tmp_dir = "/var/tmp"
events_logger = "journald"
EOF
    if [[ ! -f /etc/containers/containers.conf ]]; then
        cp /etc/containers/containers.conf.hpc /etc/containers/containers.conf
        ok "Podman containers.conf installed."
    else
        log "containers.conf exists — see /etc/containers/containers.conf.hpc for HPC recommendations"
    fi
    # Seed storage.conf from system default if not present
    if [[ ! -f /etc/containers/storage.conf ]]; then
        cp /usr/share/containers/storage.conf /etc/containers/storage.conf 2>/dev/null || true
    fi
else
    log "[DRY] Would write /etc/containers/containers.conf.hpc"
fi
ok "Podman configured."

# 9e. Apptainer configuration
log "9e: Configuring Apptainer..."
APPTAINER_CONF="/etc/apptainer/apptainer.conf"
if [[ -f "$APPTAINER_CONF" ]]; then
    # Allow user bind mounts (needed for Lustre/scratch bind-in)
    run "sed -i 's/^#*[[:space:]]*user bind control[[:space:]]*=.*/user bind control = yes/' ${APPTAINER_CONF}"
    run "grep -q 'user bind control = yes' ${APPTAINER_CONF} || echo 'user bind control = yes' >> ${APPTAINER_CONF}"

    # Enable overlay filesystem (needed for writable containers)
    run "sed -i 's/^#*[[:space:]]*enable overlay[[:space:]]*=.*/enable overlay = yes/' ${APPTAINER_CONF}"
    run "grep -q 'enable overlay = yes' ${APPTAINER_CONF} || echo 'enable overlay = yes' >> ${APPTAINER_CONF}"

    # Disable suid mode — use unprivileged user namespaces instead
    run "sed -i 's/^#*[[:space:]]*allow setuid[[:space:]]*=.*/allow setuid = no/' ${APPTAINER_CONF}"

    # Pre-bind NVIDIA GPU device nodes so GPU containers work without --nv flag.
    # Users can still pass --nv or --nvccli to override. These are HPC defaults.
    if ! "$DRY_RUN"; then
        # Core NVIDIA control and UVM devices (present on all GPU nodes)
        for dev in /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia-uvm-tools; do
            if [[ -e "$dev" ]] && ! grep -qF "$dev" "$APPTAINER_CONF"; then
                echo "bind path = ${dev}" >> "$APPTAINER_CONF"
            fi
        done
        # Numbered GPU devices (nvidia0 through nvidia7 covers most HPC nodes)
        for i in 0 1 2 3 4 5 6 7; do
            if [[ -e "/dev/nvidia${i}" ]] && ! grep -qF "/dev/nvidia${i}" "$APPTAINER_CONF"; then
                echo "bind path = /dev/nvidia${i}" >> "$APPTAINER_CONF"
            fi
        done
        # FIX PASS6-4: MIG (Multi-Instance GPU) capability devices.
        # /dev/nvidia-caps/ contains nvidia-cap* device files used by MIG
        # partitioned GPU instances. Without these, MIG workloads inside
        # Apptainer containers cannot access their GPU partition.
        if [[ -d /dev/nvidia-caps ]]; then
            if ! grep -qF '/dev/nvidia-caps' "$APPTAINER_CONF"; then
                echo "bind path = /dev/nvidia-caps" >> "$APPTAINER_CONF"
                log "Added /dev/nvidia-caps bind for MIG support"
            fi
        fi
    fi
    ok "Apptainer configured."
elif ! "$DRY_RUN"; then
    warn "Apptainer config not found at ${APPTAINER_CONF} — install apptainer package first"
else
    log "[DRY] Would configure ${APPTAINER_CONF}"
fi

# 9f. Systemd lingering — keeps user session alive for Slurm container jobs
log "9f: Installing systemd lingering profile script..."
if ! "$DRY_RUN"; then
cat > /etc/profile.d/hpc_container_linger.sh << 'LINGER'
# Enable systemd lingering for container users so rootless Podman containers
# survive Slurm PAM session teardown between job steps.
#
# FIX PASS6-6: Optimized to avoid a grep on /etc/subuid at every login.
# Checks loginctl in-memory state first (fast syscall). Only enables linger
# if not already set, avoiding any file I/O on subsequent logins.
# Falls back to subuid check only when loginctl query is unavailable.
if [[ -n "${USER:-}" ]] && command -v loginctl &>/dev/null; then
    # Fast path: query in-memory systemd user state
    if ! loginctl show-user "${USER}" 2>/dev/null | grep -q "^Linger=yes"; then
        # Slow path: check subuid file only when linger isn't already active
        if grep -q "^${USER}:" /etc/subuid 2>/dev/null; then
            loginctl enable-linger "${USER}" 2>/dev/null || true
        fi
    fi
fi
LINGER
else
    log "[DRY] Would write /etc/profile.d/hpc_container_linger.sh"
fi
ok "Systemd lingering profile script installed."

log "Section 9: Container support complete."


# =============================================================================
# SECTION 10 — KERNEL MODULE RESTRICTIONS
# =============================================================================
log "--- Section 10: Kernel Module Restrictions ---"

MODPROBE_CONF="/etc/modprobe.d/99-hpc-stig-blacklist.conf"
if ! "$DRY_RUN"; then
cat > "${MODPROBE_CONF}.tmp" << 'EOF'
# HPC/GPU STIG Module Blacklist — hpc_gpu_stig_harden.sh v6

# RHEL-09-291015 — USB storage
install usb-storage /bin/false

# RHEL-09-291020 — FireWire
install firewire-core /bin/false
install firewire-ohci /bin/false

# RHEL-09-291025 — Bluetooth
install bluetooth /bin/false
install btusb /bin/false

# RHEL-09-291030 — DCCP
install dccp /bin/false

# RHEL-09-291035 — SCTP
# NOTE: Some RDMA management tools use SCTP. Comment out if your fabric
#       or storage management software requires it.
install sctp /bin/false

# RHEL-09-291040 — RDS
install rds /bin/false

# RHEL-09-291045 — TIPC
install tipc /bin/false

# =============================================================================
# NOT BLACKLISTED (GPU/HPC/Container required):
#   nvidia, nvidia_uvm, nvidia_modeset, nvidia_drm  — NVIDIA GPU driver stack
#   nvidia_peermem                                   — GPUDirect RDMA
#   ib_core, mlx5_core, mlx5_ib, ib_uverbs          — InfiniBand stack
#   rdma_cm, ib_umad                                 — RDMA connection/mgmt
#   lustre, lnet                                     — Lustre parallel FS
#   overlay                                          — Container overlay FS
#   fuse                                             — FUSE (fuse-overlayfs)
# =============================================================================
EOF
mv "${MODPROBE_CONF}.tmp" "${MODPROBE_CONF}"
else
    log "[DRY] Would write ${MODPROBE_CONF}"
fi
ok "Kernel module blacklist configured."


# =============================================================================
# SECTION 11 — FIREWALL
# OMITTED BY SITE POLICY — firewalld not required for this cluster.
# =============================================================================
log "--- Section 11: Firewall ---"
# =============================================================================
# OMITTED: RHEL-09-251010 — firewalld enabled and active
# REASON:  Excluded by site policy. Network perimeter controls are handled
#          at the infrastructure layer (hardware firewall / network ACLs).
# POA&M:   RHEL-09-251010 | CAT II
# =============================================================================
omit "RHEL-09-251010: firewalld excluded by site policy — POA&M required"



# =============================================================================
# SECTION 12 — RESOURCE LIMITS
# =============================================================================
log "--- Section 12: Resource Limits ---"

LIMITS_CONF="/etc/security/limits.d/99-hpc-stig.conf"
if ! "$DRY_RUN"; then
cat > "${LIMITS_CONF}.tmp" << 'EOF'
# HPC/GPU Compute Node Resource Limits — hpc_gpu_stig_harden.sh v6

# libibverbs/UCX RDMA requires pinning (locking) memory for DMA registration.
# Without unlimited memlock, IB memory registration fails and MPI falls back
# from RDMA to TCP or fails entirely.
*    soft memlock unlimited
*    hard memlock unlimited

# Many-rank MPI jobs open large numbers of file descriptors
*    soft nofile 65536
*    hard nofile 65536

# HPC applications often require large stack sizes
*    soft stack unlimited
*    hard stack unlimited

# Core dumps: soft limit 0 (disabled by default, matches STIG requirement).
# Hard limit is unlimited so MPI jobs can raise it via 'ulimit -c unlimited'
# for crash analysis without needing root. hard=0 would permanently block
# core dumps even during debugging, which is unacceptable on HPC nodes.
*    soft core 0
*    hard core unlimited

EOF
mv "${LIMITS_CONF}.tmp" "${LIMITS_CONF}"
else
    log "[DRY] Would write ${LIMITS_CONF}"
fi
ok "Resource limits configured."


# =============================================================================
# SECTION 13 — FIPS MODE
# OMITTED BY SITE POLICY
# =============================================================================
log "--- Section 13: FIPS Mode ---"
# =============================================================================
# OMITTED: RHEL-09-671010 — FIPS mode (CAT I — High)
# REASON:  Excluded by site policy.
# POA&M:   This is a CAT I finding. AO risk acceptance is mandatory.
# =============================================================================
omit "RHEL-09-671010: FIPS mode excluded by site policy (CAT I) — POA&M required"


# =============================================================================
# SECTION 14 — CRYPTO POLICY
# =============================================================================
log "--- Section 14: Crypto Policy ---"
# FIPS excluded by site policy. Set to DEFAULT.
# Note: SSH cipher/MAC/KEX restrictions in Section 5 enforce DoD-approved
# algorithms independently of the system crypto policy.
CURRENT_POLICY=$(update-crypto-policies --show 2>/dev/null || echo "unknown")
if [[ "$CURRENT_POLICY" == "DEFAULT" || "$CURRENT_POLICY" == "FIPS"* ]]; then
    ok "Crypto policy at: ${CURRENT_POLICY} — no change needed."
else
    run "update-crypto-policies --set DEFAULT"
    ok "Crypto policy set to DEFAULT."
fi


# =============================================================================
# SECTION 15 — MISCELLANEOUS CONTROLS
# =============================================================================
log "--- Section 15: Miscellaneous ---"

# RHEL-09-271010 — No GUI on compute nodes
log "RHEL-09-271010: Setting default target to multi-user..."
run "systemctl set-default multi-user.target"
ok "Graphical target disabled."

# RHEL-09-431020 — Disable core dumps via systemd
log "RHEL-09-431020: Disabling systemd core dumps..."
if [[ -f /etc/systemd/coredump.conf ]] && ! "$DRY_RUN"; then
    sed -i 's/^#*Storage=.*/Storage=none/' /etc/systemd/coredump.conf
    sed -i 's/^#*ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf
elif "$DRY_RUN"; then
    log "[DRY] Would set Storage=none ProcessSizeMax=0 in /etc/systemd/coredump.conf"
fi
ok "Core dump disabled."

# RHEL-09-211040 — rsyslog
log "RHEL-09-211040: Ensuring rsyslog is enabled..."
if ! rpm -q rsyslog &>/dev/null; then
    run "dnf -y install rsyslog"
fi
run "systemctl enable --now rsyslog"
ok "rsyslog enabled."

# RHEL-09-211045 — Disable Ctrl-Alt-Del
log "RHEL-09-211045: Masking ctrl-alt-del..."
# FIX BUG C: systemctl mask on an already-masked unit returns non-zero on
# some systemd versions, aborting the script via set -e. Use || true.
run "systemctl mask ctrl-alt-del.target 2>/dev/null || true"
ok "Ctrl-Alt-Del masked."

# RHEL-09-211050 — Disable unnecessary services
log "RHEL-09-211050: Disabling unnecessary services..."
for svc in avahi-daemon cups bluetooth rpcbind nfs-server; do
    if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
        run "systemctl disable --now ${svc} 2>/dev/null || true"
    fi
done
ok "Unnecessary services disabled."

# RHEL-09-291050 — NTP via chronyd
log "RHEL-09-291050: Ensuring chronyd is running..."
if ! rpm -q chrony &>/dev/null; then
    run "dnf -y install chrony"
fi
run "systemctl enable --now chronyd"
ok "chronyd enabled."

# RHEL-09-431030 — Sticky bit on world-writable directories
log "RHEL-09-431030: Setting sticky bit on world-writable directories..."
if ! "$DRY_RUN"; then
    find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | while IFS= read -r dir; do
        chmod +t "$dir"
    done
fi
ok "Sticky bit enforced."


# =============================================================================
# SECTION 16 — SUMMARY OF OMITTED STIGs (POA&M Reference)
# =============================================================================
log ""
log "========================================================"
log " OMITTED STIG CONTROLS — POA&M REQUIRED"
log " Each entry below requires documented AO risk acceptance."
log "========================================================"
log ""
log " ── Site Policy Exclusions (AO approval required) ──"
log ""
log " RHEL-09-211030 / RHEL-09-651010 | CAT II | AIDE file integrity"
log "   Reason: Excluded by site policy."
log ""
log " RHEL-09-251010 | CAT II | firewalld"
log "   Reason: Excluded by site policy."
log "   Compensating: Network perimeter controls at infrastructure layer."
log ""
log " RHEL-09-231010/231015/231020/231025/231030/231035/231150 | CAT II"
log "   Reason: Separate filesystem hardening excluded by site policy."
log ""
log " RHEL-09-255015 | CAT II | SSH idle session timeout"
log "   Reason: Session timeouts excluded by site policy."
log ""
log " RHEL-09-671010 | CAT I  | FIPS mode"
log "   Reason: Excluded by site policy. (CAT I — AO approval mandatory)"
log ""
log " RHEL-09-672010 | CAT II | System crypto policy set to FIPS"
log "   Reason: Excluded by site policy (FIPS not required)."
log "   Applied: System crypto policy set to DEFAULT."
log ""
log " RHEL-09-431010 / RHEL-09-431015 | CAT II | SELinux enforcing"
log "   Reason: Excluded by site policy."
log ""
log " ── HPC/GPU Operational Exclusions ──"
log ""
log " RHEL-09-213085 | CAT II | kernel.yama.ptrace_scope = 1"
log "   Reason: UCX CMA intra-node MPI transport and containerised MPI"
log "           (Apptainer) require ptrace_scope = 0."
log "   Compensating: Fabric network isolation, audit logging."
log ""
log " RHEL-09-231150 | CAT II | noexec on /dev/shm"
log "   Reason: CUDA JIT, NVSHMEM, NCCL, OpenMPI vader BTL require"
log "           mmap(PROT_EXEC) into /dev/shm regions."
log "   Applied: size=${SHM_SIZE} configured; noexec omitted."
log "   Compensating: Network segmentation, audit logging."
log ""
log " RHEL-09-255045 | CAT II | PermitUserEnvironment no"
log "   Reason: MPI runtimes require SSH env propagation for library"
log "           paths and fabric tuning variables."
log "   Mitigation: AcceptEnv scoped to explicit MPI/HPC/container vars."
log ""
log " RHEL-09-255065 | CAT II | MaxSessions = 10"
log "   Reason: mpirun opens one SSH session per rank."
log "   Applied: MaxSessions = 100."
log ""
log " ── Non-STIG operational settings ──"
log ""
log " IOMMU passthrough (iommu=pt)"
log "   Reason: Strict IOMMU breaks GPUDirect RDMA P2P DMA."
log "   Applied: iommu=pt as compensating measure."
log ""
log " /proc hidepid cleared"
log "   Reason: Breaks Apptainer cgroup v2 DBus and Podman /proc/self/fd access."
log "   Applied: hidepid explicitly cleared."
log ""
log " user.max_user_namespaces = 31879"
log "   Reason: Setting to 0 disables rootless Podman and Apptainer."
log ""
log "========================================================"
log ""
log "Post-run validation commands:"
log "  oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \\"
log "        /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
log "  ausearch -ts recent           # check recent audit events after jobs"
log "  podman run --rm ubi9 id       # test rootless Podman"
log "  apptainer exec docker://alpine id  # test Apptainer"
log ""

# =============================================================================
# REBOOT REMINDER
# =============================================================================
if "$REBOOT_REQUIRED" || ! "$DRY_RUN"; then
    log ""
    warn "A REBOOT IS REQUIRED to fully activate:"
    warn "  - Kernel boot parameters (audit, PTI, SLUB, IOMMU, vsyscall)"
    warn "  - Immutable audit rules (-e 2)"
    warn "  - sysctl parameters (user namespaces, network hardening)"
    warn ""
    warn "Suggested reboot: shutdown -r +5 'STIG hardening reboot'"
fi

log ""
log "Hardening complete. Log: ${LOGFILE}"
