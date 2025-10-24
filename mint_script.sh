#!/bin/bash

# Linux Mint 21 Security Hardening Script
# Run with sudo: sudo bash security_hardening.sh

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

echo -e "${GREEN}=== Linux Mint 21 Security Hardening Script ===${NC}\n"

# Backup important files
echo -e "${YELLOW}Creating backups...${NC}"
mkdir -p /root/security_backups_$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/security_backups_$(date +%Y%m%d_%H%M%S)"
cp /etc/passwd "$BACKUP_DIR/passwd.bak"
cp /etc/shadow "$BACKUP_DIR/shadow.bak"
cp /etc/sudoers "$BACKUP_DIR/sudoers.bak"
cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
cp /etc/login.defs "$BACKUP_DIR/login.defs.bak"
cp /etc/pam.d/common-password "$BACKUP_DIR/common-password.bak"
echo -e "${GREEN}Backups created in: $BACKUP_DIR${NC}\n"

# 1. Check and remove unauthorized users
echo -e "${YELLOW}Step 1: Checking for unauthorized users...${NC}"
echo "Current users with login shells:"
awk -F: '$7 !~ /nologin|false/ {print $1}' /etc/passwd

# Check if authorized_users.txt exists
if [ -f "authorized_users.txt" ]; then
    echo -e "${GREEN}Reading authorized users from authorized_users.txt${NC}"
    mapfile -t AUTH_ARRAY < <(grep -v '^#' authorized_users.txt | grep -v '^[[:space:]]*$')
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
EOF

# Configure automatic security updates
apt-get install -y unattended-upgrades -qq
dpkg-reconfigure -plow unattended-upgrades

# Install and configure fail2ban
apt-get install -y fail2ban -qq
systemctl enable fail2ban
systemctl start fail2ban

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 22
EOF

systemctl restart fail2ban

# Disable unnecessary services
systemctl disable avahi-daemon 2>/dev/null
systemctl stop avahi-daemon 2>/dev/null
systemctl disable cups 2>/dev/null
systemctl stop cups 2>/dev/null
systemctl disable bluetooth 2>/dev/null
systemctl stop bluetooth 2>/dev/null

# Set restrictive permissions on important files
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /boot/grub/grub.cfg 2>/dev/null

# Disable core dumps
echo "* hard core 0" >> /etc/security/limits.conf

# Enable TCP SYN cookie protection
cat >> /etc/sysctl.conf <<EOF

# Security hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
EOF

sysctl -p

echo -e "${GREEN}Additional security measures applied:${NC}"
echo "  - Disabled unused filesystems"
echo "  - Enabled automatic security updates"
echo "  - Installed and configured fail2ban"
echo "  - Disabled unnecessary services (avahi, cups, bluetooth)"
echo "  - Set restrictive file permissions"
echo "  - Enabled kernel security parameters"
echo ""

# 9. Generate security report
echo -e "${YELLOW}Step 9: Generating security report...${NC}"
REPORT_FILE="$BACKUP_DIR/security_report.txt"

cat > "$REPORT_FILE" <<EOF
Security Hardening Report
Date: $(date)

Authorized Users:
$(for user in "${AUTH_ARRAY[@]}"; do echo "  - $user"; done)

Active Services:
$(systemctl list-units --type=service --state=running | grep -E "ssh|ufw|fail2ban")

Firewall Status:
$(ufw status verbose)

Open Ports:
$(ss -tulpn)

Failed Login Attempts (last 20):
$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20)
EOF

echo -e "${GREEN}Security report saved to: $REPORT_FILE${NC}\n"

# Final summary
echo -e "${GREEN}=== Security Hardening Complete ===${NC}"
echo -e "${GREEN}Summary of changes:${NC}"
echo "  ✓ Unauthorized users removed"
echo "  ✓ Common password applied to authorized users"
echo "  ✓ Root login disabled"
echo "  ✓ Strong password policies enforced"
echo "  ✓ SSH secured and enabled"
echo "  ✓ UFW firewall enabled"
echo "  ✓ Samba removed"
echo "  ✓ Fail2ban installed and configured"
echo "  ✓ Unnecessary services disabled"
echo "  ✓ Kernel hardening applied"
echo ""
echo -e "${YELLOW}IMPORTANT: Test SSH access before logging out!${NC}"
echo -e "${YELLOW}Backups stored in: $BACKUP_DIR${NC}"
echo ""
echo -e "${GREEN}All changes applied successfully!${NC}" | tr -d '[:space:]'
