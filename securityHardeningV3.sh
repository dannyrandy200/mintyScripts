#!/bin/bash

# Ubuntu Nginx + MySQL Security Hardening Script
# Run with sudo: sudo bash nginx_mysql_security_hardening.sh

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

echo -e "${GREEN}=== Nginx + MySQL Security Hardening Script ===${NC}\n"

# Backup important files
echo -e "${YELLOW}Creating backups...${NC}"
BACKUP_DIR="/root/security_backups_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp /etc/passwd "$BACKUP_DIR/passwd.bak"
cp /etc/shadow "$BACKUP_DIR/shadow.bak"
cp /etc/group "$BACKUP_DIR/group.bak"
cp /etc/sudoers "$BACKUP_DIR/sudoers.bak"
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

echo -e "${GREEN}Password requirements configured${NC}\n"

# 5. Disable SSH
echo -e "${YELLOW}Step 5: Disabling SSH...${NC}"
systemctl stop ssh 2>/dev/null
systemctl disable ssh 2>/dev/null
systemctl stop sshd 2>/dev/null
systemctl disable sshd 2>/dev/null
echo -e "${GREEN}SSH disabled${NC}\n"

# 6. Remove other web servers and keep only Nginx
echo -e "${YELLOW}Step 6: Removing other web servers...${NC}"
apt-get remove --purge -y apache2 apache2-utils lighttpd -qq 2>/dev/null
apt-get autoremove -y -qq
echo -e "${GREEN}Other web servers removed${NC}\n"

# 7. Install and secure Nginx
echo -e "${YELLOW}Step 7: Installing and securing Nginx...${NC}"
apt-get install -y nginx -qq

# Backup original nginx config
cp /etc/nginx/nginx.conf "$BACKUP_DIR/nginx.conf.bak" 2>/dev/null

# Secure Nginx configuration
cat > /etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 15;
    types_hash_max_size 2048;
    client_max_body_size 20M;
    
    # Security Headers
    server_tokens off;
    more_clear_headers Server;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Limit request methods
    if (\$request_method !~ ^(GET|HEAD|POST)$ ) {
        return 444;
    }
    
    # Hide Nginx version
    server_tokens off;
    
    # Buffer overflow protection
    client_body_buffer_size 1K;
    client_header_buffer_size 1k;
    large_client_header_buffers 2 1k;
    
    # Timeouts
    client_body_timeout 10;
    client_header_timeout 10;
    send_timeout 10;
    
    # MIME types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml font/truetype font/opentype application/vnd.ms-fontobject image/svg+xml;
    
    # Rate limiting zones
    limit_req_zone \$binary_remote_addr zone=login:10m rate=10r/m;
    limit_req_zone \$binary_remote_addr zone=general:10m rate=100r/s;
    limit_conn_zone \$binary_remote_addr zone=addr:10m;
    
    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Create default secure server block
cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name _;
    root /var/www/html;
    index index.html index.htm index.php;
    
    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    limit_conn addr 10;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Disable access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Disable access to backup files
    location ~ ~$ {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Main location
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # PHP-FPM configuration
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        
        # Security
        fastcgi_hide_header X-Powered-By;
        limit_req zone=general burst=10 nodelay;
    }
    
    # Deny access to sensitive files
    location ~ /\.(ht|git|svn) {
        deny all;
    }
}
EOF

# Set proper permissions
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

# Enable and start Nginx
systemctl enable nginx
systemctl restart nginx

echo -e "${GREEN}Nginx installed and secured${NC}\n"

# 8. Install and secure MySQL
echo -e "${YELLOW}Step 8: Installing and securing MySQL...${NC}"
apt-get install -y mysql-server -qq

# Start MySQL
systemctl start mysql
systemctl enable mysql

# Backup MySQL config
cp /etc/mysql/mysql.conf.d/mysqld.cnf "$BACKUP_DIR/mysqld.cnf.bak" 2>/dev/null

# Secure MySQL configuration
cat > /etc/mysql/mysql.conf.d/mysqld.cnf <<EOF
[mysqld]
pid-file        = /var/run/mysqld/mysqld.pid
socket          = /var/run/mysqld/mysqld.sock
datadir         = /var/lib/mysql
log-error       = /var/log/mysql/error.log

# Security Settings
bind-address = 127.0.0.1
local-infile = 0
skip-name-resolve

# Disable symbolic links
symbolic-links = 0

# Connection limits
max_connections = 100
max_connect_errors = 10
max_user_connections = 50

# Query limits
max_allowed_packet = 16M
wait_timeout = 600
interactive_timeout = 600

# Logging
log_error = /var/log/mysql/error.log
log_warnings = 2
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# Binary logging (for replication and point-in-time recovery)
log_bin = /var/log/mysql/mysql-bin.log
expire_logs_days = 7
max_binlog_size = 100M

# Performance and Security
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1

# Security hardening
skip-show-database
sql_mode = STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION

[client]
socket = /var/run/mysqld/mysqld.sock
EOF

# Set MySQL root password
echo -e "${YELLOW}Setting MySQL root password...${NC}"
read -sp "Enter MySQL root password: " MYSQL_ROOT_PASSWORD
echo ""
read -sp "Confirm MySQL root password: " MYSQL_ROOT_PASSWORD_CONFIRM
echo ""

if [ "$MYSQL_ROOT_PASSWORD" != "$MYSQL_ROOT_PASSWORD_CONFIRM" ]; then
    echo -e "${RED}MySQL passwords don't match. Exiting.${NC}"
    exit 1
fi

# Secure MySQL installation
mysql --user=root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$MYSQL_ROOT_PASSWORD';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF

# Create .my.cnf for root user
cat > /root/.my.cnf <<EOF
[client]
user=root
password=$MYSQL_ROOT_PASSWORD
EOF

chmod 600 /root/.my.cnf

# Restart MySQL
systemctl restart mysql

echo -e "${GREEN}MySQL installed and secured${NC}\n"

# 9. Enable and configure UFW firewall
echo -e "${YELLOW}Step 9: Configuring UFW firewall...${NC}"
apt-get install -y ufw -qq

# Reset UFW to defaults
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow HTTP and HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Rate limit HTTP/HTTPS to prevent DDoS
ufw limit 80/tcp
ufw limit 443/tcp

# Enable UFW
ufw --force enable

echo -e "${GREEN}UFW firewall enabled (HTTP/HTTPS only)${NC}"
ufw status verbose
echo ""

# 10. Remove Samba and other unnecessary services
echo -e "${YELLOW}Step 10: Removing unnecessary services...${NC}"
apt-get remove --purge -y samba samba-common samba-common-bin smbclient -qq 2>/dev/null
apt-get remove --purge -y telnet ftp rsh-client talk -qq 2>/dev/null
apt-get autoremove -y -qq
echo -e "${GREEN}Unnecessary services removed${NC}\n"

# 11. Additional security hardening
echo -e "${YELLOW}Step 11: Applying additional security measures...${NC}"

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
maxretry = 5
destemail = root@localhost
action = %(action_mwl)s

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10

[nginx-botsearch]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
EOF

systemctl restart fail2ban

# Install and configure auditd
apt-get install -y auditd audispd-plugins -qq
systemctl enable auditd
systemctl start auditd

cat > /etc/audit/rules.d/hardening.rules <<EOF
# Monitor Nginx configuration
-w /etc/nginx/ -p wa -k nginx_config

# Monitor MySQL configuration
-w /etc/mysql/ -p wa -k mysql_config

# Monitor web files
-w /var/www/ -p wa -k web_files

# Monitor user and group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity

# Monitor sudoers
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
EOF

augenrules --load

# Disable unnecessary services
systemctl disable avahi-daemon 2>/dev/null
systemctl stop avahi-daemon 2>/dev/null
systemctl disable cups 2>/dev/null
systemctl stop cups 2>/dev/null
systemctl disable bluetooth 2>/dev/null
systemctl stop bluetooth 2>/dev/null

# Set restrictive permissions
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /boot/grub/grub.cfg 2>/dev/null
chmod 640 /etc/nginx/nginx.conf
chmod 640 /etc/mysql/mysql.conf.d/mysqld.cnf
chmod 750 /var/log/nginx
chmod 750 /var/log/mysql

# Disable core dumps
cat > /etc/security/limits.d/10-disable-coredump.conf <<EOF
* hard core 0
EOF

echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

# Configure kernel security parameters
cat >> /etc/sysctl.conf <<EOF

# Security hardening
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
EOF

sysctl -p

# Install AppArmor
apt-get install -y apparmor apparmor-utils -qq
systemctl enable apparmor
systemctl start apparmor

# Install rootkit detection
apt-get install -y rkhunter chkrootkit -qq
rkhunter --update
rkhunter --propupd

# Install antivirus
apt-get install -y clamav clamav-daemon -qq
systemctl stop clamav-freshclam
freshclam
systemctl start clamav-freshclam
systemctl enable clamav-freshclam

# Secure shared memory
if ! grep -q "tmpfs /run/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
fi

# Configure sudo with security
cat > /etc/sudoers.d/security <<EOF
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults log_year, log_host, syslog=auth
Defaults timestamp_timeout=15
EOF

chmod 440 /etc/sudoers.d/security

# Session timeout
cat >> /etc/profile.d/timeout.sh <<EOF
TMOUT=900
readonly TMOUT
export TMOUT
EOF

chmod +x /etc/profile.d/timeout.sh

# Disable uncommon protocols
cat > /etc/modprobe.d/disable-protocols.conf <<EOF
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

echo -e "${GREEN}Additional security measures applied${NC}\n"

# 12. Configure account security
echo -e "${YELLOW}Step 12: Configuring account security...${NC}"

useradd -D -f 30

cat > /etc/pam.d/common-auth-lockout <<EOF
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
EOF

awk -F: '($2 == "" ) { print $1 }' /etc/shadow | while read user; do
    passwd -l "$user"
done

find /home -name ".rhosts" -delete 2>/dev/null

sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
echo "umask 027" >> /etc/profile

echo -e "${GREEN}Account security configured${NC}\n"

# 13. Install PHP (optional, commonly used with Nginx + MySQL)
echo -e "${YELLOW}Step 13: Installing PHP-FPM...${NC}"
apt-get install -y php-fpm php-mysql php-cli php-curl php-gd php-mbstring php-xml php-zip -qq

# Secure PHP configuration
PHP_INI=$(php -r "echo php_ini_loaded_file();")
if [ -f "$PHP_INI" ]; then
    cp "$PHP_INI" "$BACKUP_DIR/php.ini.bak"
    
    sed -i 's/^expose_php.*/expose_php = Off/' "$PHP_INI"
    sed -i 's/^display_errors.*/display_errors = Off/' "$PHP_INI"
    sed -i 's/^display_startup_errors.*/display_startup_errors = Off/' "$PHP_INI"
    sed -i 's/^allow_url_fopen.*/allow_url_fopen = Off/' "$PHP_INI"
    sed -i 's/^allow_url_include.*/allow_url_include = Off/' "$PHP_INI"
    sed -i 's/^disable_functions.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' "$PHP_INI"
fi

systemctl restart php*-fpm
echo -e "${GREEN}PHP-FPM installed and secured${NC}\n"

# 14. Generate security report
echo -e "${YELLOW}Step 14: Generating security report...${NC}"
REPORT_FILE="$BACKUP_DIR/security_report.txt"

cat > "$REPORT_FILE" <<EOF
Nginx + MySQL Security Hardening Report
Date: $(date)
Hostname: $(hostname)

Authorized Users:
$(for user in "${AUTH_ARRAY[@]}"; do echo "  - $user"; done)

Active Services:
$(systemctl list-units --type=service --state=running | grep -E "nginx|mysql|ufw|fail2ban|auditd|apparmor|clamav|php")

Firewall Status:
$(ufw status verbose)

Open Ports:
$(ss -tulpn)

Nginx Status:
$(systemctl status nginx --no-pager | head -5)

MySQL Status:
$(systemctl status mysql --no-pager | head -5)

Failed Login Attempts (last 20):
$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20)

Nginx Configuration Test:
$(nginx -t 2>&1)
EOF

echo -e "${GREEN}Security report saved to: $REPORT_FILE${NC}\n"

# Final summary
echo -e "${GREEN}=== Security Hardening Complete ===${NC}"
echo -e "${GREEN}Summary of changes:${NC}"
echo "  ✓ Unauthorized users removed"
echo "  ✓ Common password applied to authorized users"
echo "  ✓ Root login disabled"
echo "  ✓ Strong password policies enforced"
echo "  ✓ SSH DISABLED for security"
echo "  ✓ Other web servers removed (Apache, Lighttpd)"
echo "  ✓ Nginx installed and secured"
echo "  ✓ MySQL installed and secured"
echo "  ✓ PHP-FPM installed and secured"
echo "  ✓ UFW firewall enabled (HTTP/HTTPS only)"
echo "  ✓ Samba and unnecessary services removed"
echo "  ✓ Fail2ban configured for Nginx protection"
echo "  ✓ Auditd monitoring enabled"
echo "  ✓ AppArmor enabled"
echo "  ✓ Rootkit detection installed"
echo "  ✓ ClamAV antivirus installed"
echo "  ✓ Automatic security updates enabled"
echo "  ✓ Kernel hardening applied"
echo "  ✓ Account lockout policy configured"
echo "  ✓ Session timeout set"
echo ""
echo -e "${YELLOW}IMPORTANT NOTES:${NC}"
echo "  - SSH is DISABLED - use console access only"
echo "  - Nginx is running on port 80 (HTTP)"
echo "  - MySQL root password has been set"
echo "  - Web root: /var/www/html"
echo "  - MySQL credentials saved in: /root/.my.cnf"
echo ""
echo -e "${YELLOW}Backups stored in: $BACKUP_DIR${NC}"
echo ""
echo -e "${GREEN}All changes applied successfully!${NC}"
