#!/bin/bash

# Set audit directory for logs
AUDITDIR="/tmp/$(hostname -s)_audit"
mkdir -p "$AUDITDIR"

# Get OS version information
. /etc/os-release
MAIN_VERSION_ID="$(echo "$VERSION_ID" | cut -f1 -d'.')"

# Ensure the OS version is supported
if [[ "$MAIN_VERSION_ID" -lt 20 ]]; then
  echo "OS release lower than 20 is not supported. You are running $VERSION_ID. Exiting."
  exit 1
fi

# Configuration Variables (Readonly)
readonly COMPANY_NAME="BOB-SYSTEM"
readonly NEW_SSH_PORT=2222  # Change to desired SSH port
readonly UFW_ALLOW_PORTS=(
    80    # HTTP
    443   # HTTPS
    "${NEW_SSH_PORT}" # SSH
)
readonly SSH_CONFIG="/etc/ssh/sshd_config"

# Disable legacy filesystems
LEGACY_FS_CONFIG="/etc/modprobe.d/CIS.conf"
echo "Disabling legacy filesystems..."
cat > "$LEGACY_FS_CONFIG" << EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install vfat /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install usb-storage /bin/true
EOF

echo "Legacy filesystems disabled."

# Secure /dev/shm by adding recommended mount options
readonly DEV_SHM_OPTIONS="tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
readonly FSTAB="/etc/fstab"

# Backup /etc/fstab before making changes
cp "$FSTAB" "$FSTAB.bak"
echo "Backup of fstab created."

# Check and update /dev/shm entry in /etc/fstab
if grep -qE '^tmpfs\s+/dev/shm' "$FSTAB"; then
    sed -i 's|^tmpfs\s\+/dev/shm.*|'"$DEV_SHM_OPTIONS"'|' "$FSTAB"
    echo "/dev/shm entry updated in $FSTAB."
else
    echo "$DEV_SHM_OPTIONS" >> "$FSTAB"
    echo "New /dev/shm entry added to $FSTAB."
fi

# Remount /dev/shm with new options
if mount -o remount /dev/shm; then
    echo "/dev/shm successfully remounted with new options."
else
    echo "Failed to remount /dev/shm. Please check manually."
fi

# Function to remove a package if installed
remove_package() {
    local package="$1"
    if dpkg -l | grep -q "^ii  $package "; then
        echo "Removing $package..."
        apt-get remove --purge -y "$package" >> "$AUDITDIR/service_remove_$TIME.log" 2>&1
        echo "$package removed."
    else
        echo "$package is not installed or already removed." >> "$AUDITDIR/service_remove_$TIME.log"
    fi
}

# Define package lists
readonly legacy_services=(
    prelink apport autofs avahi-daemon isc-dhcp-server nis rsh-client talk telnet ldap-utils ftp nftables
)

readonly other_services=(
    dnsmasq bind9 vsftpd slapd dovecot-imapd dovecot-pop3d ypserv cups rpcbind rsync samba snmpd tftpd-hpa squid apache2 xinetd net-snmp
)

# Remove legacy and other unnecessary services
echo "Removing legacy services..."
for service in "${legacy_services[@]}"; do
    remove_package "$service"
done

echo "Removing other services..."
for service in "${other_services[@]}"; do
    remove_package "$service"
done

echo "Package removal process completed."

# Install necessary security packages
echo "Installing security packages..."
apt update && apt-get install -y sudo aide apparmor chrony auditd audispd-plugins ufw libpam-runtime libpam-modules libpam-pwquality

echo "Disabling unnecessary services..."
readonly servicelist=(dhcpd avahi-daemon cups nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd)
for service in "${servicelist[@]}"; do
  systemctl disable "$service" 2>/dev/null || echo "$service is already disabled."
done

# Set password quality policies
echo "Setting password quality policies..."
readonly pwquality_options=(
    "minlen = 14"
    "dcredit = -1"
    "ucredit = -1"
    "ocredit = -1"
    "lcredit = -1"
    "retry = 3"
)

for option in "${pwquality_options[@]}"; do
    key="${option%%=*}"
    if grep -q "^$key" /etc/security/pwquality.conf; then
        sed -i "s/^$key.*/$option/" /etc/security/pwquality.conf
    else
        echo "$option" >> /etc/security/pwquality.conf
    fi

done

# Function to apply pam_faillock configuration
function apply_pam_faillock_remediation {
    echo "Applying pam_faillock remediation..."

    # Create or update pam_faillock profiles
    local pam_configs_dir="/usr/share/pam-configs"
    local profiles=(
        "faillock:Enable pam_faillock to deny access:0:Auth: [default=die] pam_faillock.so authfail"
        "faillock_notify:Notify of failed login attempts and reset count upon success:1024:Auth: requisite pam_faillock.so preauth\nAccount: required pam_faillock.so"
    )

    for profile in "${profiles[@]}"; do
        IFS=':' read -r file_name title priority content <<< "$profile"
        local file_path="${pam_configs_dir}/${file_name}"
        
        if [ ! -f "$file_path" ]; then
            echo "Creating pam_faillock profile: $file_name"
            cat << EOF > "$file_path"
Name: $title
Default: yes
Priority: $priority
Auth-Type: Primary
$content
EOF
            echo "Profile $file_name created."
        else
            echo "Profile $file_name already exists."
        fi
    done

    # Apply PAM changes using pam-auth-update
    pam-auth-update --enable faillock faillock_notify

    echo "pam_faillock remediation applied successfully."
}

# Function to remediate faillock configuration
function remediate_faillock_conf {
    echo "Remediating /etc/security/faillock.conf configuration..."
    local config_file="/etc/security/faillock.conf"
    local settings=(
        "deny = 5"
        "unlock_time = 900"
    )

    # Create file if it doesn't exist
    if [ ! -f "$config_file" ]; then
        touch "$config_file"
        echo "Created $config_file"
    fi

    # Update each setting
    for setting in "${settings[@]}"; do
        local option=${setting%% =*}
        
        if grep -qE "^\s*${option}\s*=" "$config_file"; then
            # Setting exists, update it
            sed -i -E "s/^\s*${option}\s*=\s*[0-9]+/${setting}/" "$config_file"
            echo "Updated $setting in $config_file"
        else
            # Setting doesn't exist, add it
            echo "$setting" >> "$config_file"
            echo "Added $setting to $config_file"
        fi
    done
}

# Function to configure journald
function configure_journald {
    echo "Setting journald configuration..."
    local config_file="/etc/systemd/journald.conf"
    local settings=(
        "Compress=yes"
        "ForwardToSyslog=no"
        "Storage=persistent"
        "SystemMaxUse=100M"
        "SystemKeepFree=50M"
        "RuntimeMaxUse=30M"
        "RuntimeKeepFree=10M"
        "MaxFileSec=1day"
    )

    # Ensure the config file exists
    if [ ! -f "$config_file" ]; then
        echo "Creating $config_file"
        mkdir -p "$(dirname "$config_file")"
        touch "$config_file"
    fi

    # Update each setting
    for setting in "${settings[@]}"; do
        local option=${setting%%=*}
        
        if grep -q "^${option}=" "$config_file"; then
            # Option exists, update it
            sed -i "s/^${option}=.*/${setting}/" "$config_file"
            echo "Updated $setting in $config_file"
        elif grep -q "^#${option}=" "$config_file"; then
            # Option is commented, uncomment and update
            sed -i "s/^#${option}=.*/${setting}/" "$config_file"
            echo "Uncommented and updated $setting in $config_file"
        else
            # Option doesn't exist, add it
            echo "$setting" >> "$config_file"
            echo "Added $setting to $config_file"
        fi
    done
}

# Main execution
echo "Starting system hardening process..."

# Apply PAM faillock remediation
apply_pam_faillock_remediation

# Remediate faillock configuration
remediate_faillock_conf

# Configure journald
configure_journald

# Function to configure system security limits
function configure_security_limits() {
    echo "Setting core dump security limits..."
    echo '* hard core 0' > /etc/security/limits.conf
    echo "Core dump limits configured."
}

# Function to configure rsyslog
function configure_rsyslog() {
    echo "Configuring additional logging..."
    
    local rsyslog_config="/etc/rsyslog.d/CIS.conf"
    cat > "$rsyslog_config" << EOF
\$FileCreateMode 0640
auth            /var/log/secure
kern.*          /var/log/messages
daemon.*        /var/log/messages
syslog.*        /var/log/messages
EOF
    
    chmod 600 "$rsyslog_config"
    echo "Additional logs configured."
}

# Function to configure audit daemon
function configure_auditd() {
    echo "Configuring audit daemon..."
    
    # Enable auditd service
    systemctl enable auditd
    
    # Backup original configuration
    local audit_conf="/etc/audit/auditd.conf"
    if [ ! -f "${audit_conf}.bak" ]; then
        cp -a "$audit_conf" "${audit_conf}.bak"
    fi
    
    # Configure audit log storage and behavior
    local audit_settings=(
        "space_left_action = email"
        "action_mail_acct = root"
        "admin_space_left_action = halt"
        "max_log_file_action = keep_logs"
    )
    
    for setting in "${audit_settings[@]}"; do
        local option=${setting%% =*}
        sed -i "s/^${option}.*$/${setting}/" "$audit_conf"
    done
    
    echo "Audit daemon configured."
}

# Function to set up comprehensive audit rules
function configure_audit_rules() {
    echo "Setting audit rules..."
    
    local rules_file="/etc/audit/rules.d/CIS.rules"
    cat > "$rules_file" << "EOF"
-D
-b 320

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Identity monitoring
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# System locale monitoring
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Login monitoring
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Session monitoring
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Permission modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Access monitoring
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Mount monitoring
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Deletion monitoring
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Privilege scope changes
-w /etc/sudoers -p wa -k scope

# Admin actions
-w /var/log/sudo.log -p wa -k actions

# Module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# MAC policy
-w /etc/selinux/ -p wa -k MAC-policy

# Ensure audit is immutable
-e 2
EOF
    
    # Generate audit rules
    echo "Generating audit rules..."
    augenrules
    
    echo "Audit rules configured."
}

# Function to configure cron
function configure_cron() {
    echo "Configuring Cron and Anacron..."
    
    # Install cron packages if needed
    apt-get install -y cron anacron
    
    # Enable cron service
    systemctl enable cron
    
    # Secure cron files
    local cron_files=("anacrontab" "crontab" "cron.hourly" "cron.daily" "cron.weekly" "cron.monthly")
    for file in "${cron_files[@]}"; do
        if [ -f "/etc/$file" ]; then
            chown root:root "/etc/$file"
            chmod 600 "/etc/$file"
        fi
    done
    
    # Secure cron directory
    if [ -d "/etc/cron.d" ]; then
        chmod 700 "/etc/cron.d"
    fi
    
    echo "Cron configuration secured."
}

# Function to configure at and cron allow files
function configure_access_controls() {
    echo "Configuring at/cron access controls..."
    
    local control_files=("at" "cron")
    for file in "${control_files[@]}"; do
        # Create/secure allow files
        touch "/etc/${file}.allow"
        chown root:root "/etc/${file}.allow"
        chmod 600 "/etc/${file}.allow"
        
        # Remove deny files
        if [ -f "/etc/${file}.deny" ]; then
            rm -f "/etc/${file}.deny"
        fi
    done
    
    echo "Access controls configured."
}

# Function to configure SSH banner
function configure_ssh_banner() {
    echo "Configuring SSH banner..."
    
    # Enable banner in SSH config
    sed -i 's/\#Banner none/Banner \/etc\/issue\.net/' /etc/ssh/sshd_config
    
    # Backup original issue.net if not already backed up
    if [ ! -f "$AUDITDIR/issue.net_$TIME.bak" ] && [ -f "/etc/issue.net" ]; then
        local AUDITDIR="${AUDITDIR:-/var/log/audit}"
        local TIME=$(date +%Y%m%d-%H%M%S)
        
        # Create audit directory if it doesn't exist
        mkdir -p "$AUDITDIR"
        
        # Backup issue.net
        cp -p "/etc/issue.net" "$AUDITDIR/issue.net_$TIME.bak"
    fi
    
    echo "SSH banner configured. You need to add banner content to /etc/issue.net"
}

# Main function
function main() {
    # Create audit directory and set timestamp if not provided
    AUDITDIR="${AUDITDIR:-/var/log/audit}"
    TIME="${TIME:-$(date +%Y%m%d-%H%M%S)}"
    
    # Create audit directory if it doesn't exist
    mkdir -p "$AUDITDIR"
    
    # Execute hardening functions
    configure_security_limits
    configure_rsyslog
    configure_auditd
    configure_audit_rules
    configure_cron
    configure_access_controls
    configure_ssh_banner
    
    echo "System hardening completed successfully."
}

# Execute main function
main


# Function to configure system banners
function configure_banners() {
    echo "Configuring system banners..."
    
    # Variables
    local TIME="${TIME:-$(date +%Y%m%d-%H%M%S)}"
    local AUDITDIR="${AUDITDIR:-/var/log/audit}"
    local COMPANY_NAME="${COMPANY_NAME:-RESTRICTED ACCESS}"
    
    # Create audit directory if it doesn't exist
    mkdir -p "$AUDITDIR"
    
    # Configure MOTD
    if [ -f /etc/motd ]; then
        cp -p /etc/motd "$AUDITDIR/motd_$TIME.bak"
    fi
    
    cat > /etc/motd << EOF
$COMPANY_NAME AUTHORIZED USE ONLY
EOF
    
    # Configure /etc/issue
    if [ -f /etc/issue ] && [ ! -L /etc/issue ]; then
        cp -p /etc/issue "$AUDITDIR/issue_$TIME.bak"
        rm -f /etc/issue
    fi
    
    # Create symlink for issue
    if [ ! -L /etc/issue ]; then
        ln -sf /etc/issue.net /etc/issue
    fi
    
    echo "System banners configured."
}

# Function to harden SSH configuration
function harden_ssh() {
    echo "Hardening SSH configuration..."
    
    # Variables
    local TIME="${TIME:-$(date +%Y%m%d-%H%M%S)}"
    local AUDITDIR="${AUDITDIR:-/var/log/audit}"
    local SSH_CONFIG="${SSH_CONFIG:-/etc/ssh/sshd_config}"
    local NEW_SSH_PORT="${NEW_SSH_PORT:-22}"
    
    # Create audit directory if it doesn't exist
    mkdir -p "$AUDITDIR"
    
    # Backup current SSH config
    echo "Creating a backup of current SSH configuration..."
    if [ -f "$SSH_CONFIG" ]; then
        cp -p "$SSH_CONFIG" "$AUDITDIR/sshd_config_$TIME.bak"
    fi
    
    # Array of SSH hardening settings
    local ssh_settings=(
        "LogLevel INFO"
        "Protocol 2"
        "X11Forwarding no"
        "MaxAuthTries 4"
        "IgnoreRhosts yes"
        "HostbasedAuthentication no"
        "PasswordAuthentication no"
        "PermitRootLogin no"
        "PermitEmptyPasswords no"
        "PermitUserEnvironment no"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 0"
        "LoginGraceTime 60"
        "UsePAM yes"
        "MaxStartups 10:30:60"
        "MaxSessions 10"
        "AllowTcpForwarding no"
        "MACs hmac-sha2-512,hmac-sha2-256"
        "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
    )
    
    # Apply SSH hardening settings
    echo "Applying SSH hardening settings..."
    for setting in "${ssh_settings[@]}"; do
        local option=$(echo "$setting" | awk '{print $1}')
        
        if grep -Eiq "^\s*${option}\s" "$SSH_CONFIG"; then
            # Replace existing option
            sed -i "s|^\s*${option}.*|${setting}|g" "$SSH_CONFIG"
        else
            # Append if not found
            echo "$setting" >> "$SSH_CONFIG"
        fi
    done
    
    # Set SSH port
    echo "Setting SSH port to $NEW_SSH_PORT..."
    if grep -q "^Port" "$SSH_CONFIG"; then
        sed -i "s/^Port .*/Port $NEW_SSH_PORT/" "$SSH_CONFIG"
    else
        echo "Port $NEW_SSH_PORT" >> "$SSH_CONFIG"
    fi
    
    # Secure SSH host keys
    echo "Securing SSH host keys..."
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod go-wx {} \;
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;
    
    # Set permissions on sshd_config
    if [ -f "$SSH_CONFIG" ]; then
        chown root:root "$SSH_CONFIG"
        chmod 600 "$SSH_CONFIG"
    fi
    
    # Validate SSH configuration before restart
    echo "Validating SSH configuration..."
    if command -v sshd >/dev/null 2>&1; then
        if sshd -t; then
            echo "SSHD configuration is valid."
            systemctl restart sshd
            echo "SSHD restarted successfully." | tee -a "$AUDITDIR/service_restart_$TIME.log"
        else
            echo "ERROR: SSHD configuration is invalid. Check logs." | tee -a "$AUDITDIR/service_restart_$TIME.log"
            return 1
        fi
    else
        echo "WARNING: SSHD binary not found. Skipping validation."
    fi
    
    echo "SSH hardening completed successfully."
}

# Function to configure user environment
function configure_user_environment() {
    echo "Configuring user environment settings..."
    
    # Configure umask
    echo "Setting default umask for users..."
    for file in /etc/profile /etc/bash.bashrc; do
        if [ -f "$file" ]; then
            if grep -q "^[[:space:]]*umask" "$file"; then
                sed -i 's/^[[:space:]]*umask[[:space:]]*[0-9]\+/umask 027/g' "$file"
            else
                echo "umask 027" >> "$file"
            fi
        fi
    done
    
    # Configure TMOUT
    echo "Setting default TMOUT for users..."
    for file in /etc/profile /etc/bash.bashrc; do
        if [ -f "$file" ]; then
            if ! grep -q "TMOUT" "$file"; then
                echo "TMOUT=900" >> "$file"
                echo "export TMOUT" >> "$file"
            fi
        fi
    done
    
    echo "User environment configured."
}

# Function to harden system configuration
function harden_system_configuration() {
    echo "Applying system hardening configurations..."
    
    # Set grub.cfg permissions
    echo "Setting grub.cfg permissions..."
    if [ -f /boot/grub/grub.cfg ]; then
        chmod 600 /boot/grub/grub.cfg
        chown root:root /boot/grub/grub.cfg
    fi
    
    # Configure AIDE integrity check
    echo "Configuring AIDE integrity check..."
    if command -v aide.wrapper >/dev/null 2>&1; then
        (crontab -l 2>/dev/null || echo "") | grep -q "aide.wrapper" || {
            (crontab -l 2>/dev/null || echo "") | { cat; echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"; } | crontab -
        }
    else
        echo "WARNING: AIDE not installed. Skipping AIDE configuration."
    fi
    
    # Configure logrotate
    echo "Setting logrotate.conf configurations..."
    if [ -f /etc/logrotate.conf ]; then
        sed -i -E 's/create\s+[0-9]*/create 0640 root utmp/g' /etc/logrotate.conf
    fi
    
    # Secure log files
    echo "Securing log files..."
    find /var/log -type f -exec chmod g-wx,o-rwx {} \; 2>/dev/null || true
    find /var/log -type d -exec chmod g-w,o-rwx {} \; 2>/dev/null || true
    
    echo "System configuration hardened."
}

# Function to configure user account security
function configure_account_security() {
    echo "Configuring user account security..."
    
    # Lock inactive user accounts
    echo "Locking inactive user accounts..."
    useradd -D -f 30
    
    # Configure login.defs
    echo "Setting login.defs configurations..."
    local login_settings=(
        "PASS_MAX_DAYS 90"
        "PASS_MIN_DAYS 7"
        "PASS_WARN_AGE 7"
    )
    
    for setting in "${login_settings[@]}"; do
        local option=${setting%% *}
        
        if grep -q "^${option}" /etc/login.defs; then
            sed -i "s/^${option}.*/${setting}/g" /etc/login.defs
        else
            echo "$setting" >> /etc/login.defs
        fi
    done
    
    echo "User account security configured."
}

# Main function
function main() {
    # Set default variables
    TIME=$(date +%Y%m%d-%H%M%S)
    AUDITDIR="${AUDITDIR:-/var/log/audit}"
    SSH_CONFIG="${SSH_CONFIG:-/etc/ssh/sshd_config}"
    NEW_SSH_PORT="${NEW_SSH_PORT:-22}"
    COMPANY_NAME="${COMPANY_NAME:-RESTRICTED ACCESS}"
    
    # Create audit directory
    mkdir -p "$AUDITDIR"
    
    # Execute hardening functions
    configure_banners
    harden_ssh
    configure_user_environment
    harden_system_configuration
    configure_account_security
    
    echo "System hardening completed successfully."
}

# Execute main function
main

# Function to verify and set critical file permissions
function verify_system_file_permissions() {
    echo "Verifying System File Permissions..."
    
    # Define critical files and their permissions
    declare -A critical_files=(
        ["/etc/passwd"]="644:root:root"
        ["/etc/shadow"]="640:root:root"
        ["/etc/gshadow"]="640:root:root"
        ["/etc/group"]="644:root:root"
        ["/etc/rsyslog.conf"]="600:root:root"
    )
    
    # Set permissions and ownership for critical files
    for file in "${!critical_files[@]}"; do
        if [ -f "$file" ]; then
            perms=$(echo ${critical_files[$file]} | cut -d: -f1)
            owner=$(echo ${critical_files[$file]} | cut -d: -f2)
            group=$(echo ${critical_files[$file]} | cut -d: -f3)
            
            echo "Setting permissions on $file to $perms, owner to $owner:$group"
            chmod $perms "$file"
            chown $owner:$group "$file"
        else
            echo "Warning: $file not found"
        fi
    done
    
    # Handle grub config file
    for grub_file in "/boot/grub/grub.cfg" "/boot/grub2/grub.cfg"; do
        if [ -f "$grub_file" ]; then
            echo "Setting permissions on $grub_file to 600"
            chmod 600 "$grub_file"
            chown root:root "$grub_file"
        fi
    done
    
    echo "System file permissions verified and set."
}

# Function to set sticky bit on world-writable directories
function set_sticky_bit() {
    echo "Setting Sticky Bit on All World-Writable Directories..."
    
    # Ensure audit directory exists
    mkdir -p "$AUDITDIR"
    
    # Find world-writable directories without sticky bit and set it
    df --local -P | awk '{if (NR!=1) print $6}' | \
    xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | \
    tee "$AUDITDIR/sticky_on_world_$TIME.log" | \
    xargs -r chmod a+t
    
    echo "Sticky bit set on world-writable directories."
}

# Function to find and log world-writable files
function find_world_writable_files() {
    echo "Searching for world writable files..."
    
    # Find world-writable files
    df --local -P | awk '{if (NR!=1) print $6}' | \
    xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | \
    tee "$AUDITDIR/world_writable_files_$TIME.log"
    
    echo "World-writable files search completed."
}

# Function to find and log files with no owner or group
function find_unowned_files() {
    echo "Searching for Un-owned files and directories..."
    
    # Find files with no owner
    df --local -P | awk '{if (NR!=1) print $6}' | \
    xargs -I '{}' find '{}' -xdev -nouser -ls 2>/dev/null | \
    tee "$AUDITDIR/unowned_files_$TIME.log"
    
    echo "Searching for Un-grouped files and directories..."
    
    # Find files with no group
    df --local -P | awk '{if (NR!=1) print $6}' | \
    xargs -I '{}' find '{}' -xdev -nogroup -ls 2>/dev/null | \
    tee "$AUDITDIR/ungrouped_files_$TIME.log"
    
    echo "Unowned files search completed."
}

# Function to find and log SUID/SGID executables
function find_privileged_executables() {
    echo "Searching for SUID/SGID System Executables..."
    
    # Find SUID executables
    df --local -P | awk '{if (NR!=1) print $6}' | \
    xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print 2>/dev/null | \
    tee "$AUDITDIR/suid_exec_$TIME.log"
    
    # Find SGID executables
    df --local -P | awk '{if (NR!=1) print $6}' | \
    xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print 2>/dev/null | \
    tee "$AUDITDIR/sgid_exec_$TIME.log"
    
    echo "Privileged executables search completed."
}

# Function to check for empty password fields
function check_empty_passwords() {
    echo "Searching for empty password fields..."
    
    # Find users with empty passwords
    if [ -f /etc/shadow ]; then
        grep -E '^[^:]+::' /etc/shadow | cut -d: -f1 | \
        xargs -I '{}' echo "{} does not have a password" | \
        tee "$AUDITDIR/empty_passwd_$TIME.log"
    else
        echo "Warning: /etc/shadow not found" | tee "$AUDITDIR/empty_passwd_$TIME.log"
    fi
    
    echo "Empty password check completed."
}

# Function to review user and group settings
function review_user_group_settings() {
    echo "Reviewing User and Group Settings..."
    
    # Create output file
    echo "Reviewing User and Group Settings..." > "$AUDITDIR/reviewusrgrp_$TIME.log"
    
    # Check for '+:' entries in passwd, shadow, and group
    for file in /etc/passwd /etc/shadow /etc/group; do
        if [ -f "$file" ]; then
            grep -E '^\+:' "$file" >> "$AUDITDIR/reviewusrgrp_$TIME.log" 2>/dev/null
        fi
    done
    
    # Check for users with UID 0 (root)
    if [ -f /etc/passwd ]; then
        echo "Users with UID 0:" >> "$AUDITDIR/reviewusrgrp_$TIME.log"
        awk -F: '($3 == 0) { print $1 }' /etc/passwd >> "$AUDITDIR/reviewusrgrp_$TIME.log"
    fi
    
    echo "User and group settings review completed."
}

# Function to check root PATH integrity
function check_root_path() {
    echo "Checking root PATH integrity..."
    
    # Create output file
    > "$AUDITDIR/root_path_$TIME.log"
    
    # Check for empty directories in PATH
    if [[ "$PATH" == *::* ]]; then
        echo "Empty Directory in PATH (::)" >> "$AUDITDIR/root_path_$TIME.log"
    fi
    
    # Check for trailing colon in PATH
    if [[ "$PATH" == *: ]]; then
        echo "Trailing : in PATH" >> "$AUDITDIR/root_path_$TIME.log"
    fi
    
    # Check each directory in PATH
    IFS=':' read -ra path_dirs <<< "$PATH"
    for dir in "${path_dirs[@]}"; do
        # Check if directory is current directory
        if [ "$dir" = "." ]; then
            echo "PATH contains ." >> "$AUDITDIR/root_path_$TIME.log"
            continue
        fi
        
        # Check if directory exists
        if [ -d "$dir" ]; then
            # Check permissions
            dirperm=$(ls -ldH "$dir" 2>/dev/null | cut -f1 -d" ")
            if [ -n "$dirperm" ]; then
                # Check if group writable
                if [ "${dirperm:5:1}" != "-" ]; then
                    echo "Group Write permission set on directory $dir" >> "$AUDITDIR/root_path_$TIME.log"
                fi
                
                # Check if world writable
                if [ "${dirperm:8:1}" != "-" ]; then
                    echo "Other Write permission set on directory $dir" >> "$AUDITDIR/root_path_$TIME.log"
                fi
            fi
            
            # Check ownership
            dirown=$(ls -ldH "$dir" 2>/dev/null | awk '{print $3}')
            if [ "$dirown" != "root" ]; then
                echo "$dir is not owned by root" >> "$AUDITDIR/root_path_$TIME.log"
            fi
        else
            echo "$dir is not a directory" >> "$AUDITDIR/root_path_$TIME.log"
        fi
    done
    
    echo "Root PATH integrity check completed."
}

# Function to check home directory permissions
function check_home_permissions() {
    echo "Checking Permissions on User Home Directories..."
    
    # Create output file
    > "$AUDITDIR/home_permission_$TIME.log"
    
    # Get list of home directories, excluding system users
    awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false" && $1 != "root" && $1 != "halt" && $1 != "sync" && $1 != "shutdown") {print $6}' /etc/passwd | while read -r dir; do
        if [ -d "$dir" ]; then
            dirperm=$(ls -ld "$dir" 2>/dev/null | cut -f1 -d" ")
            if [ -n "$dirperm" ]; then
                # Check group write
                if [ "${dirperm:5:1}" != "-" ]; then
                    echo "Group Write permission set on directory $dir" >> "$AUDITDIR/home_permission_$TIME.log"
                fi
                
                # Check other read
                if [ "${dirperm:7:1}" != "-" ]; then
                    echo "Other Read permission set on directory $dir" >> "$AUDITDIR/home_permission_$TIME.log"
                fi
                
                # Check other write
                if [ "${dirperm:8:1}" != "-" ]; then
                    echo "Other Write permission set on directory $dir" >> "$AUDITDIR/home_permission_$TIME.log"
                fi
                
                # Check other execute
                if [ "${dirperm:9:1}" != "-" ]; then
                    echo "Other Execute permission set on directory $dir" >> "$AUDITDIR/home_permission_$TIME.log"
                fi
            fi
        fi
    done
    
    echo "Home directory permissions check completed."
}

# Function to check dot file permissions
function check_dot_file_permissions() {
    echo "Checking User Dot File Permissions..."
    
    # Create output file
    > "$AUDITDIR/dotfile_permission_$TIME.log"
    
    # Get list of home directories, excluding system users
    awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false" && $1 != "root" && $1 != "sync" && $1 != "halt" && $1 != "shutdown") {print $6}' /etc/passwd | while read -r dir; do
        if [ -d "$dir" ]; then
            # Check dot files in home directory
            find "$dir" -maxdepth 1 -name ".[A-Za-z0-9]*" -type f ! -path "*/\.*" 2>/dev/null | while read -r file; do
                if [ ! -h "$file" ] && [ -f "$file" ]; then
                    fileperm=$(ls -l "$file" 2>/dev/null | cut -f1 -d" ")
                    if [ -n "$fileperm" ]; then
                        # Check group write
                        if [ "${fileperm:5:1}" != "-" ]; then
                            echo "Group Write permission set on file $file" >> "$AUDITDIR/dotfile_permission_$TIME.log"
                        fi
                        
                        # Check other write
                        if [ "${fileperm:8:1}" != "-" ]; then
                            echo "Other Write permission set on file $file" >> "$AUDITDIR/dotfile_permission_$TIME.log"
                        fi
                    fi
                fi
            done
        fi
    done
    
    echo "Dot file permissions check completed."
}

# Function to check .netrc file permissions
function check_netrc_permissions() {
    echo "Checking Permissions on User .netrc Files..."
    
    # Create output file
    > "$AUDITDIR/netrd_permission_$TIME.log"
    
    # Get list of home directories, excluding system users
    awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false" && $1 != "root" && $1 != "sync" && $1 != "halt" && $1 != "shutdown") {print $6}' /etc/passwd | while read -r dir; do
        if [ -d "$dir" ]; then
            # Check .netrc file
            file="$dir/.netrc"
            if [ -f "$file" ] && [ ! -h "$file" ]; then
                fileperm=$(ls -l "$file" 2>/dev/null | cut -f1 -d" ")
                if [ -n "$fileperm" ]; then
                    # Check group permissions
                    if [ "${fileperm:4:1}" != "-" ]; then
                        echo "Group Read set on $file" >> "$AUDITDIR/netrd_permission_$TIME.log"
                    fi
                    if [ "${fileperm:5:1}" != "-" ]; then
                        echo "Group Write set on $file" >> "$AUDITDIR/netrd_permission_$TIME.log"
                    fi
                    if [ "${fileperm:6:1}" != "-" ]; then
                        echo "Group Execute set on $file" >> "$AUDITDIR/netrd_permission_$TIME.log"
                    fi
                    
                    # Check other permissions
                    if [ "${fileperm:7:1}" != "-" ]; then
                        echo "Other Read set on $file" >> "$AUDITDIR/netrd_permission_$TIME.log"
                    fi
                    if [ "${fileperm:8:1}" != "-" ]; then
                        echo "Other Write set on $file" >> "$AUDITDIR/netrd_permission_$TIME.log"
                    fi
                    if [ "${fileperm:9:1}" != "-" ]; then
                        echo "Other Execute set on $file" >> "$AUDITDIR/netrd_permission_$TIME.log"
                    fi
                fi
            fi
        fi
    done
    
    echo ".netrc file permissions check completed."
}

# Main function
function main() {
    # Set default variables if not already set
    TIME="${TIME:-$(date +%Y%m%d-%H%M%S)}"
    AUDITDIR="${AUDITDIR:-/var/log/audit}"
    
    # Create audit directory if it doesn't exist
    mkdir -p "$AUDITDIR"
    
    # Run security checks
    verify_system_file_permissions
    set_sticky_bit
    find_world_writable_files
    find_unowned_files
    find_privileged_executables
    check_empty_passwords
    review_user_group_settings
    check_root_path
    check_home_permissions
    check_dot_file_permissions
    check_netrc_permissions
    
    echo "File permission and security checks completed."
}

# Execute main function
main


# Set up audit directory and timestamp
AUDITDIR="/var/log/security_audit"
TIME=$(date +%Y%m%d-%H%M%S)

# Create audit directory if it doesn't exist
mkdir -p $AUDITDIR

echo "Starting Linux Hardening Process..."

echo "Checking for Presence of User .rhosts Files..."
for dir in $(grep -v '^\(root\|halt\|sync\|shutdown\):' /etc/passwd | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $6 }'); do
    if [ -d "$dir" ]; then
        for file in $dir/.rhosts; do
            if [ ! -h "$file" -a -f "$file" ]; then
                echo ".rhosts file in $dir" >> $AUDITDIR/rhosts_$TIME.log
            fi
        done
    fi
done

echo "Checking Groups in /etc/passwd..."
for i in $(cut -s -d: -f4 /etc/passwd | sort -u); do
    if ! grep -q -P "^.*?:x:$i:" /etc/group; then
        echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking That Users Are Assigned Home Directories..."
awk -F: '{ print $1 " " $3 " " $6 }' /etc/passwd | while read user uid dir; do
    if [ $uid -ge 500 -a ! -d "$dir" -a "$user" != "nfsnobody" -a "$user" != "nobody" ]; then
        echo "The home directory ($dir) of user $user does not exist." >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking That Defined Home Directories Exist..."
awk -F: '{ print $1 " " $3 " " $6 }' /etc/passwd | while read user uid dir; do
    if [ $uid -ge 500 -a -d "$dir" -a "$user" != "nfsnobody" -a "$user" != "nobody" ]; then
        owner=$(stat -L -c "%U" "$dir" 2>/dev/null)
        if [ "$owner" != "$user" ]; then
            echo "The home directory ($dir) of user $user is owned by $owner." >> $AUDITDIR/audit_$TIME.log
        fi
    fi
done

echo "Checking for Duplicate UIDs..."
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read count uid; do
    if [ -n "$count" ] && [ "$count" -gt 1 ]; then
        users=$(awk -F: '($3 == n) { print $1 }' n=$uid /etc/passwd | xargs)
        echo "Duplicate UID ($uid): ${users}" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Duplicate GIDs..."
cut -f3 -d":" /etc/group | sort -n | uniq -c | while read count gid; do
    if [ -n "$count" ] && [ "$count" -gt 1 ]; then
        groups=$(awk -F: '($3 == n) { print $1 }' n=$gid /etc/group | xargs)
        echo "Duplicate GID ($gid): ${groups}" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking That Reserved UIDs Are Assigned to System Accounts..."
defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games
gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser
nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid
named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"

awk -F: '($3 < 500) { print $1" "$3 }' /etc/passwd | while read user uid; do
    found=0
    for tUser in ${defUsers}; do
        if [ "${user}" = "${tUser}" ]; then
            found=1
            break
        fi
    done
    if [ $found -eq 0 ]; then
        echo "User $user has a reserved UID ($uid)." >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Duplicate User Names..."
cut -f1 -d":" /etc/passwd | sort | uniq -c | while read count username; do
    if [ -n "$count" ] && [ "$count" -gt 1 ]; then
        uids=$(awk -F: '($1 == n) { print $3 }' n=$username /etc/passwd | xargs)
        echo "Duplicate User Name ($username): ${uids}" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Duplicate Group Names..."
cut -f1 -d":" /etc/group | sort | uniq -c | while read count groupname; do
    if [ -n "$count" ] && [ "$count" -gt 1 ]; then
        gids=$(awk -F: '($1 == n) { print $3 }' n=$groupname /etc/group | xargs)
        echo "Duplicate Group Name ($groupname): ${gids}" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Presence of User .netrc Files..."
awk -F: '{ print $6 }' /etc/passwd | while read dir; do
    if [ -d "$dir" ] && [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
        echo ".netrc file $dir/.netrc exists" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Presence of User .forward Files..."
awk -F: '{ print $6 }' /etc/passwd | while read dir; do
    if [ -d "$dir" ] && [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Modifying Network Parameters..."
cp /etc/sysctl.conf $AUDITDIR/sysctl.conf_$TIME.bak

cat > /etc/sysctl.d/99-CIS.conf << 'EOF'
# IP Forwarding
net.ipv4.ip_forward=0

# IP Spoofing protection
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0

# Log martian packets
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1

# Block SYN attacks
net.ipv4.tcp_syncookies=1

# Ignore broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts=1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses=1

# Disable IPv6
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0

# Flush routing table
net.ipv4.route.flush=1

# Core dump settings
fs.suid_dumpable=0

# Increase system file descriptor limit
fs.file-max=65535
EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-CIS.conf

echo "Settings in GRUB"
if [ -f /etc/default/grub ]; then
    cp /etc/default/grub $AUDITDIR/grub_$TIME.bak
    # Use sed with backup in case something goes wrong
    sed -i.bak -E 's/GRUB_CMDLINE_LINUX="(.*)"/GRUB_CMDLINE_LINUX="\1 ipv6.disable=1 apparmor=1 security=apparmor audit_backlog_limit=8192 audit=1"/g' /etc/default/grub
    
    # Only update grub if the command exists
    if command -v update-grub &> /dev/null; then
        update-grub
    elif command -v grub2-mkconfig &> /dev/null; then
        grub2-mkconfig -o /boot/grub2/grub.cfg
    else
        echo "WARNING: Could not update grub config, please run manually" >> $AUDITDIR/audit_$TIME.log
    fi
else
    echo "WARNING: /etc/default/grub not found, skipping GRUB hardening" >> $AUDITDIR/audit_$TIME.log
fi

echo "Configuring UFW (Uncomplicated Firewall)..."
# Define allowed ports - customize as needed
UFW_ALLOW_PORTS=("22/tcp" "80/tcp" "443/tcp")

# Check if UFW is installed
if command -v ufw &> /dev/null; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    for port in "${UFW_ALLOW_PORTS[@]}"; do
        ufw allow "$port"
    done

    ufw --force enable
else
    echo "WARNING: UFW not installed, skipping firewall configuration" >> $AUDITDIR/audit_$TIME.log
fi

echo "Configuring Fail2Ban..."
# Check if Fail2Ban is installed
if command -v apt &> /dev/null; then
    apt install -y fail2ban
    systemctl enable fail2ban
    systemctl start fail2ban
elif command -v yum &> /dev/null; then
    yum install -y fail2ban
    systemctl enable fail2ban
    systemctl start fail2ban
else
    echo "WARNING: Could not install Fail2Ban, package manager not found" >> $AUDITDIR/audit_$TIME.log
fi

# Add additional hardening measures
echo "Setting secure file permissions..."
chmod 0600 /etc/shadow
chmod 0600 /etc/gshadow
chmod 0644 /etc/passwd
chmod 0644 /etc/group

echo "Disabling unused services..."
for service in telnet rsh rlogin xinetd; do
    if systemctl list-unit-files | grep -q $service; then
        systemctl disable $service
        systemctl stop $service
    fi
done

# Generate completion message
clear
echo
echo
echo "============================================================================="
echo "============================================================================="
echo "===                                                                       ==="
echo "===        #     # #######    #     # ####### #######  #####  #######     ==="
echo "===        #     #    #       #     # #     # #       #     # #           ==="
echo "===        #     #    #       #     # #     # #       #       #           ==="
echo "===        #######    #       ####### #     # #####   #       #####       ==="
echo "===        #     #    #       #     # #     # #       #       #           ==="
echo "===        #     #    #       #     # #     # #       #     # #           ==="
echo "===        #     #    #       #     # ####### #        #####  #######     ==="
echo "===                                                                       ==="
echo "===                                                                       ==="
echo "===  LINUX HARDENING COMPLETED SUCCESSFULLY                               ==="
echo "===                                                                       ==="
echo "===  Audit logs located at: $AUDITDIR                                      ==="
echo "===                                                                       ==="
echo "============================================================================="
echo "============================================================================="
echo
echo

echo "Successfully Completed"
echo "Please check $AUDITDIR for details"
