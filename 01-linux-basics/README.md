# Module 1: Linux Basics for Hacking

## Overview
This module covers fundamental Linux skills required for ethical hacking and penetration testing. You'll learn system navigation, user management, process control, and essential command-line techniques.

## Module Objectives
- Master Linux file system navigation
- Understand user and permission management
- Perform system reconnaissance
- Learn process management and monitoring
- Master bash scripting fundamentals
- Automate common hacking tasks

## Lessons

### 1.1 - Linux File System & Navigation
  - File system hierarchy
  - Navigation commands (ls, cd, pwd)
- File operations (cat, head, tail, find)
  - Understanding permissions
  - SUID/SGID exploitation basics

  **Location:** `[lessons/01-file-system-navigation.md](lessons/01-file-system-navigation.md)`

### 1.2 - User & Permission Management
- User enumeration (/etc/passwd, /etc/shadow)
  - Sudo exploitation
  - Group privilege escalation
  - Credential hunting
  - Capabilities exploitation

  **Location:** `lessons/02-user-permission-management.md`

## Practice Scripts

### 1. System Reconnaissance Script
  **File:** `scripts/system_recon.sh`

  Performs comprehensive initial system enumeration:
  - System information gathering
  - User enumeration
  - SUID/SGID binary discovery
  - Writable directory identification
  - Credential hunting
  - Network configuration analysis
  - Running process enumeration
  - Cron job analysis

  **Usage:**
  ```bash
  ./scripts/system_recon.sh
  ```

  **Output:** Creates a timestamped directory with enumeration results

  ---

### 2. User Enumeration & Privilege Escalation Checker
  **File:** `scripts/user_enum.sh`

  Identifies privilege escalation vectors:
  - Current user analysis
  - Sudo privilege checking
  - Dangerous group membership
  - SUID binary exploitation opportunities
  - File capability analysis
  - Writable system file detection
  - SSH key discovery
  - Cron job analysis

  **Usage:**
  ```bash
  ./scripts/user_enum.sh
  ```

  ---

### 3. Network Scanner
  **File:** `scripts/network_scanner.sh`

  Pure bash network reconnaissance tool:
  - Local network discovery (ping sweep)
- Port scanning (common ports)
  - Service identification
  - ARP table analysis
  - Network interface enumeration
  - Banner grabbing

  **Usage:**
  ```bash
# Interactive mode
  ./scripts/network_scanner.sh

# Direct scan mode
  ./scripts/network_scanner.sh 192.168.1.10
  ```

  **Features:**
- No external dependencies (pure bash)
  - Multiple scan types
  - Service name resolution
  - Progress indication

  ---

## Hands-On Exercises

### Exercise 1: File System Exploration
1. Navigate to root (/)
  2. List all directories
  3. Find all SUID binaries: `find / -perm -4000 2>/dev/null`
  4. Locate configuration files in /etc containing "password"
  5. Find writable directories in /var

### Exercise 2: User Enumeration
  1. List all system users
  2. Identify users with bash shells
  3. Check current user privileges with `id` and `sudo -l`
  4. Search for SSH keys
  5. Analyze command history files

### Exercise 3: Process and Network Analysis
  1. List all running processes: `ps aux`
  2. Identify processes running as root
  3. Check listening ports: `ss -tulpn` or `netstat -tulpn`
  4. View active network connections
  5. Analyze cron jobs

### Exercise 4: Automation
  1. Run `system_recon.sh` and analyze output
  2. Run `user_enum.sh` and identify privilege escalation vectors
  3. Use `network_scanner.sh` to discover hosts on your network
  4. Create a custom script combining techniques from all three

  ---

## Additional Practice

### TryHackMe Rooms
- Linux Fundamentals (Parts 1-3)
  - Linux Privilege Escalation
  - Linux PrivEsc Arena

### HackTheBox Machines
  - Lame (Easy - Linux basics)
  - Shocker (Easy - Linux exploitation)
- Beep (Easy - Linux enumeration)

  ---

## Quick Reference

### Essential Commands
  ```bash
# Navigation
  pwd, cd, ls -la

# File Operations
  cat, head, tail, less, find, locate, which

# User Info
  whoami, id, groups, sudo -l

# Process Management
  ps aux, top, htop, kill, killall

# Network
  ip addr, ss -tulpn, ping, nc

# System Info
  uname -a, hostname, cat /etc/os-release

# File Permissions
  chmod, chown, chgrp

# Searching
  grep, find, locate
  ```

### Privilege Escalation Checks
  ```bash
# SUID binaries
  find / -perm -4000 -type f 2>/dev/null

# Sudo rights
  sudo -l

# Writable /etc
  find /etc -writable 2>/dev/null

# Capabilities
  getcap -r / 2>/dev/null

# Cron jobs
  cat /etc/crontab
  ls -la /etc/cron.*
  ```

  ---

## Resources

  - **GTFOBins:** https://gtfobins.github.io/ (SUID/Sudo exploitation)
  - **Explainshell:** https://explainshell.com/ (Command explanations)
  - **Linux Journey:** https://linuxjourney.com/ (Interactive tutorials)
  - **HacKTricks:** https://book.hacktricks.xyz/linux-hardening/privilege-escalation

  ---

## Progress Checklist

  - [ ] Completed Lesson 1.1 - File System & Navigation
  - [ ] Completed Lesson 1.2 - User & Permission Management
  - [ ] Executed system_recon.sh successfully
  - [ ] Executed user_enum.sh and understand output
  - [ ] Executed network_scanner.sh on local network
  - [ ] Found at least 3 SUID binaries
  - [ ] Successfully enumerated all system users
  - [ ] Identified listening network services
  - [ ] Created a custom reconnaissance script
  - [ ] Completed all hands-on exercises

  ---

  **Next Module:** [02-Networking →](../02-networking/)
