#!/usr/bin/env bash
# One-shot hardening + Docker install for a fresh Ubuntu 24.04 host.
# Idempotent. Run as root:  bash bootstrap-host.sh
#
# What it does
#   - unattended security upgrades
#   - sshd: keys only, no passwords, no root password login, no X11/agent fwd
#   - nftables firewall via ufw: allow 22/tcp (rate-limited), 80, 443; deny rest
#   - fail2ban on sshd
#   - Docker CE from Docker's repo; journald/log limits
#   - sysctl: no IP forwarding of foreign traffic, SYN cookies, no redirects
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -yq
apt-get install -yq ufw fail2ban unattended-upgrades ca-certificates curl gnupg rsync

# --- automatic security updates ---------------------------------------------
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
sed -i 's|^//\s*"${distro_id}:${distro_codename}-updates";|        "${distro_id}:${distro_codename}-updates";|' \
  /etc/apt/apt.conf.d/50unattended-upgrades

# --- sshd ----------------------------------------------------------------------
install -d -m 755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/10-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
# Hetzner cloud-init may ship a conflicting drop-in; ours must win (lexically first)
if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
  sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/50-cloud-init.conf
fi
mkdir -p /run/sshd   # socket-activated sshd on 24.04 lacks it until first use; `sshd -t` needs it
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

# --- firewall ------------------------------------------------------------------
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp comment 'ssh (rate-limited)'
ufw allow 80/tcp comment 'acme + redirect'
ufw allow 443/tcp comment 'https'
ufw allow 443/udp comment 'http3'
ufw --force enable

# --- fail2ban ------------------------------------------------------------------
cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
# Ubuntu 24.04 unit is ssh.service (fail2ban's default match is sshd.service)
journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd
maxretry = 4
findtime = 10m
bantime = 24h
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# --- kernel ---------------------------------------------------------------------
cat >/etc/sysctl.d/90-hardening.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF
sysctl --system >/dev/null

# --- docker ---------------------------------------------------------------------
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    >/etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -yq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
cat >/etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "20m", "max-file": "5" },
  "live-restore": true,
  "no-new-privileges": true
}
EOF
systemctl enable --now docker
systemctl restart docker

# --- journald -------------------------------------------------------------------
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=500M\n' >/etc/systemd/journald.conf.d/size.conf
systemctl restart systemd-journald

echo "bootstrap done:"
ufw status verbose | sed 's/^/  /'
docker --version | sed 's/^/  /'
fail2ban-client status sshd | sed 's/^/  /'
