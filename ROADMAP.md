# Linux Learning Roadmap
## For React/TypeScript Developers with Cybersecurity Interests

---

## Phase 1: Linux Fundamentals (Weeks 1-2)

### Getting Started
- [ ] Understand Linux distributions (Ubuntu, Debian, Fedora, Arch)
- [ ] Set up a Linux environment (dual boot, VM, or WSL2)
- [ ] Learn the Linux filesystem hierarchy (/, /home, /etc, /var, /usr)
- [ ] Master basic navigation: `cd`, `ls`, `pwd`, `tree`

### File Operations
- [ ] File manipulation: `cp`, `mv`, `rm`, `touch`, `mkdir`
- [ ] Viewing files: `cat`, `less`, `head`, `tail`, `nano`, `vim`
- [ ] File permissions: `chmod`, `chown`, understanding rwx notation
- [ ] Symbolic and hard links: `ln -s`

### Connection to React/TypeScript
- Understanding where Node.js and npm store packages (`/usr/local/lib/node_modules`)
- Setting up development environments on Linux
- File permissions for build artifacts and deployment

---

## Phase 2: Shell Scripting & Automation (Weeks 3-4)

### Bash Basics
- [ ] Shell variables and environment variables (`$PATH`, `$HOME`)
- [ ] Input/output redirection: `>`, `>>`, `<`, `|`
- [ ] Command chaining: `&&`, `||`, `;`
- [ ] Process management: `ps`, `top`, `htop`, `kill`, `killall`

### Scripting
- [ ] Write your first bash script with shebang (`#!/bin/bash`)
- [ ] Conditional statements (if/else)
- [ ] Loops (for, while)
- [ ] Functions in bash
- [ ] Automate development tasks (build scripts, deployment automation)

### Connection to React/TypeScript
- Automate React build processes with shell scripts
- Create deployment pipelines
- Environment variable management for different environments
- CI/CD pipeline understanding

---

## Phase 3: Networking & Services (Weeks 5-6)

### Networking Fundamentals
- [ ] Network configuration: `ip`, `ifconfig`, `netstat`, `ss`
- [ ] DNS resolution: `/etc/hosts`, `nslookup`, `dig`, `host`
- [ ] Network testing: `ping`, `traceroute`, `mtr`
- [ ] Secure remote access: `ssh`, `scp`, `rsync`
- [ ] Port scanning: `nmap`, `nc` (netcat)

### Web Services
- [ ] Install and configure Nginx/Apache
- [ ] Serve React applications with Nginx
- [ ] Reverse proxy configuration
- [ ] SSL/TLS certificates with Let's Encrypt
- [ ] Firewall basics: `ufw`, `iptables`

### Connection to React/TypeScript
- Deploying React apps on Linux servers
- Setting up Node.js backend services
- WebSocket connections and networking
- API endpoint security

---

## Phase 4: System Administration (Weeks 7-8)

### Package Management
- [ ] APT (Debian/Ubuntu): `apt install`, `apt update`, `apt upgrade`
- [ ] YUM/DNF (Red Hat/Fedora)
- [ ] Managing Node.js versions with `nvm`
- [ ] System updates and security patches

### System Monitoring
- [ ] Resource monitoring: `df`, `du`, `free`, `vmstat`, `iostat`
- [ ] Log management: `/var/log`, `journalctl`, `dmesg`
- [ ] Cron jobs for scheduled tasks
- [ ] System services: `systemd`, `systemctl`

### Users & Groups
- [ ] User management: `useradd`, `usermod`, `passwd`
- [ ] Group management: `groupadd`, `groups`
- [ ] Sudo configuration: `/etc/sudoers`
- [ ] Principle of least privilege

---

## Phase 5: Security Fundamentals (Weeks 9-11)

### Access Control & Hardening
- [ ] SSH key-based authentication
- [ ] Disable root login via SSH
- [ ] Configure fail2ban for intrusion prevention
- [ ] SELinux/AppArmor basics
- [ ] File integrity monitoring: `aide`, `tripwire`

### Firewall & Network Security
- [ ] Configure `ufw` firewall rules
- [ ] Advanced `iptables` rules
- [ ] Port knocking
- [ ] VPN setup (OpenVPN, WireGuard)
- [ ] Network traffic analysis: `tcpdump`, `wireshark`

### Vulnerability Assessment
- [ ] Security scanning with `lynis`
- [ ] Vulnerability scanning with `OpenVAS` or `Nessus`
- [ ] Basic penetration testing with Kali Linux tools
- [ ] Web application security (OWASP Top 10)

### Connection to React/TypeScript
- Securing Node.js applications on Linux
- HTTPS enforcement and SSL/TLS configuration
- Environment variable security (never commit `.env` files)
- Protecting against XSS, CSRF, and injection attacks
- Content Security Policy (CSP) headers

---

## Phase 6: Advanced Security & DevSecOps (Weeks 12-16)

### Container Security
- [ ] Docker fundamentals and security best practices
- [ ] Container image scanning: `trivy`, `clair`
- [ ] Kubernetes security basics
- [ ] Non-root containers
- [ ] Secrets management: `vault`, `sealed-secrets`

### Security Automation
- [ ] Automated security testing in CI/CD
- [ ] Static analysis: `eslint-plugin-security`, `semgrep`
- [ ] Dependency scanning: `npm audit`, `snyk`, `OWASP Dependency-Check`
- [ ] Infrastructure as Code security: `tfsec`, `checkov`

### Web Application Security
- [ ] SQL injection prevention and detection
- [ ] XSS attack vectors and mitigation (relevant to React)
- [ ] CSRF protection
- [ ] JWT security and best practices
- [ ] Rate limiting and DDoS protection
- [ ] Security headers: CSP, HSTS, X-Frame-Options

### Incident Response
- [ ] Log analysis for security events
- [ ] Detecting suspicious processes
- [ ] Memory forensics basics
- [ ] Incident response playbooks

---

## Phase 7: Advanced Linux & Cybersecurity (Weeks 17+)

### Advanced Topics
- [ ] Kernel modules and system calls
- [ ] Binary analysis: `strace`, `ltrace`, `gdb`
- [ ] Reverse engineering basics
- [ ] Exploit development fundamentals
- [ ] Buffer overflow understanding

### Red Team / Blue Team
- [ ] Offensive security: Metasploit, Burp Suite
- [ ] Defensive security: IDS/IPS (Snort, Suricata)
- [ ] Security Information and Event Management (SIEM)
- [ ] Threat hunting
- [ ] Malware analysis in Linux environments

### Certifications to Consider
- [ ] CompTIA Linux+
- [ ] LPIC-1/LPIC-2
- [ ] CompTIA Security+
- [ ] CEH (Certified Ethical Hacker)
- [ ] OSCP (Offensive Security Certified Professional)
- [ ] CISSP (for advanced career progression)

---

## Practical Projects

### Beginner Projects
1. **Personal Development Server**: Set up Nginx, deploy a React app
2. **Automated Backup Script**: Bash script to backup important files
3. **System Monitor Dashboard**: React app showing system stats via APIs

### Intermediate Projects
4. **Secure Full-Stack Application**: React + Node.js + PostgreSQL on Linux
5. **CI/CD Pipeline**: GitLab/Jenkins pipeline for React app deployment
6. **Hardened Web Server**: Security-focused Nginx configuration

### Advanced Projects
7. **Honeypot Deployment**: Set up and monitor a honeypot
8. **Security Scanner**: Build a custom web vulnerability scanner
9. **Container Security Platform**: Automated Docker image scanning pipeline
10. **SIEM Dashboard**: React-based security event monitoring system

---

## Resources

### Books
- "The Linux Command Line" by William Shotts
- "Linux Bible" by Christopher Negus
- "Web Application Security" by Andrew Hoffman
- "Penetration Testing" by Georgia Weidman

### Online Platforms
- OverTheWire (Bandit, Natas wargames)
- HackTheBox
- TryHackMe
- Linux Journey
- OWASP WebGoat

### Practice Environments
- VirtualBox/VMware for virtual machines
- Kali Linux for security testing
- Ubuntu Server for production simulation
- Docker for containerized environments

### Communities
- r/linuxquestions
- r/netsec
- Stack Overflow
- InfoSec Twitter community
- Local cybersecurity meetups

---

## Daily Practice Recommendations

- **15 minutes**: Linux command practice
- **30 minutes**: Reading documentation or security news
- **1 hour**: Hands-on project work or labs
- **Weekend**: CTF challenges or longer projects

---

## Key Principles to Remember

1. **Security First**: Always think about security implications
2. **Automation**: Automate repetitive tasks with scripts
3. **Documentation**: Document your configurations and processes
4. **Continuous Learning**: Security landscape constantly evolves
5. **Ethical Practice**: Only test systems you own or have permission to test

---

## Milestones & Goals

- **Month 1**: Comfortable with Linux terminal and basic administration
- **Month 2**: Can deploy and secure a web application on Linux
- **Month 3**: Understand networking and common security vulnerabilities
- **Month 4**: Can perform basic security assessments and hardening
- **Month 6+**: Ready for entry-level cybersecurity roles or certifications

---

**Remember**: Your React/TypeScript experience is valuable! Web application security is a critical field, and understanding both development and security gives you a unique advantage.
