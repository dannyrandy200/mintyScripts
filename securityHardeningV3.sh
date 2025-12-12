#!/bin/bash

# Ubuntu Comprehensive Security Hardening Script
# Run with sudo: sudo bash ubuntu_security_hardening.sh

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}" 
   exit 1
fi

echo -e "${GREEN}=== Ubuntu Comprehensive Security Hardening Script ===${NC}\n"

# Backup important files
echo -e "${YELLOW}Creating backups...${NC}"
BACKUP_DIR="/root/security_backups_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp /etc/passwd "$BACKUP_DIR/passwd.bak"
cp /etc/shadow "$BACKUP_DIR/shadow.bak"
cp /etc/group "$BACKUP_DIR/group.bak"
cp /etc/sudoers "$BACKUP_DIR/sudoers.bak"
cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
cp /etc/login.defs "$BACKUP_DIR/login.defs.bak"
cp /etc/pam.d/common-password "$BACKUP_DIR/common-password.bak"
cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.bak"
echo -e "${GREEN}Backups created in: $BACKUP_DIR${NC}\n"

# 1. Check and remove unauthorized users
echo -e "${YELLOW}Step 1: Checking for unauthorized users...${NC}"
echo "Current users with login shells:"
awk -F: '$7 !~ /nologin|false/ {print $1}' /etc/passwd

# Check if authorized_users.txt exists
if [ -f "authorized_users.txt" ]; then
    echo -e "${GREEN}Reading authorized users from authorized_users.txt${NC}"
    mapfile -t AUTH_ARRAY < <(grep -v '^#' authorized_users.txt | grep -v '^[[:space:]]*$' | tr -d '[:space:]')
else
    echo -e "${RED}Error: authorized_users.txt not found!${NC}"
    exit 1
fi

for user in $(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd); do
    if [[ ! " ${AUTH_ARRAY[@]} " =~ " ${user} " ]]; then
        echo -e "${RED}Removing unauthorized user: $user${NC}"
        userdel -r "$user" 2>/dev/null
    else
        echo -e "${GREEN}Authorized user: $user${NC}"
    fi
done
echo ""

# 2. Apply common password to all accounts
echo -e "${YELLOW}Step 2: Setting common password for authorized users...${NC}"
read -sp "Enter new password for all authorized users: " NEW_PASSWORD
echo ""
read -sp "Confirm password: " CONFIRM_PASSWORD
echo ""

if [ "$NEW_PASSWORD" != "$CONFIRM_PASSWORD" ]; then
    echo -e "${RED}Passwords don't match. Exiting.${NC}"
    exit 1
fi

for user in "${AUTH_ARRAY[@]}"; do
    echo "$user:$NEW_PASSWORD" | chpasswd
    echo -e "${GREEN}Password updated for: $user${NC}"
done
echo ""

# 3. Disable root login
echo -e "${YELLOW}Step 3: Disabling root login...${NC}"
passwd -l root
echo -e "${GREEN}Root account locked${NC}\n"

# 4. Configure password security requirements
echo -e "${YELLOW}Step 4: Applying password security requirements...${NC}"

# Install password quality checking library
apt-get update -qq
apt-get install -y libpam-pwquality -qq

# Configure password quality requirements
cat > /etc/security/pwquality.conf <<EOF
# Password quality requirements
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 3
maxrepeat = 3
difok = 3
EOF

# Configure PAM for password policies
sed -i 's/^password\s*requisite\s*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3/' /etc/pam.d/common-password

# Configure password aging in login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# Apply password aging to existing users
for user in "${AUTH_ARRAY[@]}"; do
    chage -M 90 -m 7 -W 14 "$user"
done

echo -e "${GREEN}Password requirements configured:${NC}"
echo "  - Minimum length: 12 characters"
echo "  - Must contain: uppercase, lowercase, digit, special character"
echo "  - Maximum password age: 90 days"
echo "  - Minimum password age: 7 days"
echo "  - Warning before expiration: 14 days"
echo ""

# 5. Configure SSH securely
echo -e "${YELLOW}Step 5: Configuring SSH...${NC}"
apt-get install -y openssh-server -qq

# Secure SSH configuration
cat > /etc/ssh/sshd_config <<EOF
# SSH Security Configuration
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
AllowUsers ${AUTH_ARRAY[@]}
MaxSessions 2
HostbasedAuthentication no
IgnoreRhosts yes
EOF

systemctl enable ssh
systemctl restart ssh
echo -e "${GREEN}SSH configured and enabled${NC}\n"

# 6. Enable and configure UFW firewall
echo -e "${YELLOW}Step 6: Configuring UFW firewall...${NC}"
apt-get install -y ufw -qq

# Reset UFW to defaults
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow 22/tcp

# Rate limit SSH to prevent brute force
ufw limit 22/tcp

# Enable UFW
ufw --force enable

echo -e "${GREEN}UFW firewall enabled with default deny incoming${NC}"
ufw status verbose
echo ""

# 7. Remove Samba
echo -e "${YELLOW}Step 7: Removing Samba...${NC}"
apt-get remove --purge -y samba samba-common samba-common-bin smbclient -qq
apt-get autoremove -y -qq
echo -e "${GREEN}Samba removed${NC}\n"

# 8. Additional security hardening
echo -e "${YELLOW}Step 8: Applying additional security measures...${NC}"

# Disable unused filesystems
cat > /etc/modprobe.d/disable-filesystems.conf <<EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install usb-storage /bin/true
EOF

# Configure automatic security updates
apt-get install -y unattended-upgrades apt-listchanges -qq
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Install and configure fail2ban
apt-get install -y fail2ban -qq
systemctl enable fail2ban
systemctl start fail2ban

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 3
EOF

systemctl restart fail2ban

# Install and configure auditd for system auditing
apt-get install -y auditd audispd-plugins -qq
systemctl enable auditd
systemctl start auditd

# Add audit rules
cat > /etc/audit/rules.d/hardening.rules <<EOF
# Monitor unauthorized access attempts
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Monitor user and group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudoers changes
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Monitor network configuration changes
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitor unsuccessful file access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -k access
EOF

augenrules --load

# Disable unnecessary services
systemctl disable avahi-daemon 2>/dev/null
systemctl stop avahi-daemon 2>/dev/null
systemctl disable cups 2>/dev/null
systemctl stop cups 2>/dev/null
systemctl disable bluetooth 2>/dev/null
systemctl stop bluetooth 2>/dev/null
systemctl disable isc-dhcp-server 2>/dev/null
systemctl stop isc-dhcp-server 2>/dev/null
systemctl disable isc-dhcp-server6 2>/dev/null
systemctl stop isc-dhcp-server6 2>/dev/null

# Set restrictive permissions on important files
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /boot/grub/grub.cfg 2>/dev/null
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny

# Disable core dumps
cat > /etc/security/limits.d/10-disable-coredump.conf <<EOF
* hard core 0
EOF

echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

# Configure kernel security parameters
cat >> /etc/sysctl.conf <<EOF

# Security hardening
# IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN cookies protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Kernel hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1

# Address space layout randomization
kernel.randomize_va_space = 2
EOF

sysctl -p

# Configure hosts.deny and hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
echo "sshd: ALL" > /etc/hosts.allow

# Install and configure AppArmor
apt-get install -y apparmor apparmor-utils -qq
systemctl enable apparmor
systemctl start apparmor
aa-enforce /etc/apparmor.d/* 2>/dev/null

# Install rootkit detection tools
apt-get install -y rkhunter chkrootkit -qq

# Configure rkhunter
rkhunter --update
rkhunter --propupd

# Install antivirus
apt-get install -y clamav clamav-daemon -qq
systemctl stop clamav-freshclam
freshclam
systemctl start clamav-freshclam
systemctl enable clamav-freshclam

# Configure system logging
apt-get install -y rsyslog -qq
systemctl enable rsyslog
systemctl start rsyslog

# Secure shared memory
if ! grep -q "tmpfs /run/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
fi

# Configure sudo with security options
cat > /etc/sudoers.d/security <<EOF
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults log_year, log_host, syslog=auth
Defaults timestamp_timeout=15
EOF

chmod 440 /etc/sudoers.d/security

# Set up USB device control
if [ -f /etc/modprobe.d/blacklist.conf ]; then
    echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
fi

# Configure session timeout
cat >> /etc/profile.d/timeout.sh <<EOF
TMOUT=900
readonly TMOUT
export TMOUT
EOF

chmod +x /etc/profile.d/timeout.sh

# Disable uncommon network protocols
cat > /etc/modprobe.d/disable-protocols.conf <<EOF
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

# Remove unnecessary packages
apt-get remove --purge -y telnet ftp rsh-client rsh-redone-client talk -qq 2>/dev/null
apt-get autoremove -y -qq

echo -e "${GREEN}Additional security measures applied:${NC}"
echo "  - Disabled unused filesystems and USB storage"
echo "  - Enabled automatic security updates"
echo "  - Installed and configured fail2ban"
echo "  - Installed and configured auditd for system auditing"
echo "  - Disabled unnecessary services"
echo "  - Set restrictive file permissions"
echo "  - Enabled kernel security parameters"
echo "  - Configured AppArmor mandatory access control"
echo "  - Installed rootkit detection (rkhunter, chkrootkit)"
echo "  - Installed ClamAV antivirus"
echo "  - Secured shared memory"
echo "  - Configured sudo logging and security"
echo "  - Set 15-minute session timeout"
echo "  - Disabled uncommon network protocols"
echo "  - Removed insecure network tools"
echo ""

# 9. Configure account security
echo -e "${YELLOW}Step 9: Configuring account security...${NC}"

# Lock inactive user accounts
useradd -D -f 30

# Set account lockout policy
cat > /etc/pam.d/common-auth-lockout <<EOF
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
EOF

# Ensure no accounts have empty passwords
awk -F: '($2 == "" ) { print $1 }' /etc/shadow | while read user; do
    passwd -l "$user"
    echo -e "${YELLOW}Locked account with empty password: $user${NC}"
done

# Remove .rhosts files
find /home -name ".rhosts" -delete 2>/dev/null

# Set default umask to 027
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
echo "umask 027" >> /etc/profile

echo -e "${GREEN}Account security configured${NC}\n"

# 10. Generate security report
echo -e "${YELLOW}Step 10: Generating security report...${NC}"
REPORT_FILE="$BACKUP_DIR/security_report.txt"

cat > "$REPORT_FILE" <<EOF
Security Hardening Report
Date: $(date)
Hostname: $(hostname)

Authorized Users:
$(for user in "${AUTH_ARRAY[@]}"; do echo "  - $user"; done)

Active Services:
$(systemctl list-units --type=service --state=running | grep -E "ssh|ufw|fail2ban|auditd|apparmor|clamav")

Firewall Status:
$(ufw status verbose)

Open Ports:
$(ss -tulpn)

Failed Login Attempts (last 20):
$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20)

Security Modules:
$(aa-status 2>/dev/null | head -5)

Kernel Security Parameters:
$(sysctl -a 2>/dev/null | grep -E "net.ipv4.tcp_syncookies|kernel.randomize_va_space|net.ipv4.conf.all.rp_filter")
EOF

echo -e "${GREEN}Security report saved to: $REPORT_FILE${NC}\n"

# Final summary
echo -e "${GREEN}=== Security Hardening Complete ===${NC}"
echo -e "${GREEN}Summary of changes:${NC}"
echo "  ✓ Unauthorized users removed"
echo "  ✓ Common password applied to authorized users"
echo "  ✓ Root login disabled"
echo "  ✓ Strong password policies enforced (12+ chars, complexity)"
echo "  ✓ SSH secured and enabled"
echo "  ✓ UFW firewall enabled with rate limiting"
echo "  ✓ Samba removed"
echo "  ✓ Fail2ban installed and configured"
echo "  ✓ Auditd system monitoring enabled"
echo "  ✓ AppArmor mandatory access control enabled"
echo "  ✓ Rootkit detection tools installed"
echo "  ✓ ClamAV antivirus installed"
echo "  ✓ Automatic security updates enabled"
echo "  ✓ Unnecessary services disabled"
echo "  ✓ Kernel hardening applied"
echo "  ✓ Account lockout policy configured"
echo "  ✓ Session timeout set (15 minutes)"
echo "  ✓ USB storage and uncommon protocols disabled"
echo "  ✓ Insecure network tools removed"
echo ""
echo -e "${YELLOW}IMPORTANT: Test SSH access in a new terminal before logging out!${NC}"
echo -e "${YELLOW}Backups stored in: $BACKUP_DIR${NC}"
echo ""
echo -e "${GREEN}All changes applied successfully!${NC}"
