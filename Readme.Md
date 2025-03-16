# Linux Hardening Script

A comprehensive security hardening script for Linux systems that implements CIS (Center for Internet Security) benchmark recommendations and industry best practices.

![Linux Security](https://img.shields.io/badge/Linux-Security-blue)
![Bash](https://img.shields.io/badge/Shell-Bash-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Overview

This script performs various security checks and hardening measures for Linux systems, helping administrators secure their environments against common threats and vulnerabilities. It is designed to work across different Linux distributions with minimal dependencies.

## Features

- **User Account Security**
  - Checks for insecure `.rhosts`, `.netrc`, and `.forward` files
  - Identifies duplicate UIDs, GIDs, and usernames
  - Validates home directory ownership and existence
  - Ensures proper reserved UID assignment

- **Network Security**
  - Disables unnecessary network protocols and functions
  - Implements kernel-level network hardening via sysctl
  - Configures IPv6 security settings or disables it entirely
  - Protects against common network attacks (SYN floods, spoofing, etc.)

- **Firewall Configuration**
  - Automatically configures UFW (Uncomplicated Firewall)
  - Sets secure default policies (deny incoming, allow outgoing)
  - Allows customizable essential services (SSH, HTTP, HTTPS)

- **Intrusion Prevention**
  - Installs and configures Fail2Ban to prevent brute force attacks
  - Implements kernel-level security enhancements

- **Audit Logging**
  - Creates detailed logs of all security checks
  - Maintains backups of modified configuration files
  - Timestamps all audit actions for future reference

## Requirements

- Root/sudo access
- Bash shell
- Linux OS (Debian/Ubuntu/CentOS/RHEL/Fedora)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/linux-hardening.git
   cd linux-hardening
   ```

2. Make the script executable:
   ```bash
   chmod +x linux_hardening.sh
   ```

3. Run with root privileges:
   ```bash
   sudo ./linux_hardening.sh
   ```

## Customization

You can customize the script to suit your specific requirements:

- Edit the `UFW_ALLOW_PORTS` array to specify which ports should be opened
- Modify the system accounts list in `defUsers` variable
- Adjust network parameters in the sysctl configuration section

## Output

The script creates an audit directory at `/var/log/security_audit` containing:
- Logs of all security issues found
- Backups of modified system files
- Timestamped records of all actions

## Warning

This script makes significant changes to system configuration. It is recommended to:
- Run this script in a test environment first
- Backup your system before running in production
- Review and understand the script before execution

## Compatibility

Tested on:
- Ubuntu 20.04/22.04
- Debian 10/11
- CentOS 7/8
- RHEL 8
- Fedora 34+

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- CIS Benchmarks for baseline security recommendations
- Various Linux security communities for best practices
- Contributors and testers who have helped improve this script

## Disclaimer

This script is provided as-is without any warranty. The author is not responsible for any damage caused by the use of this script. Use at your own risk.
