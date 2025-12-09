[#](#) Linux Fundamentals Tutorial
## Understanding the Linux Operating System

---

## Table of Contents
1. [What is Linux?](#what-is-linux)
2. [Linux Architecture](#linux-architecture)
3. [The Linux Filesystem](#the-linux-filesystem)
4. [Processes and Process Management](#processes-and-process-management)
5. [Users and Permissions](#users-and-permissions)
6. [Package Management](#package-management)
7. [System Services](#system-services)

---

## What is Linux?

Linux is an open-source, Unix-like operating system kernel created by Linus Torvalds in 1991. When we say "Linux," we typically mean a complete operating system (a distribution) that includes:

- **The Linux Kernel**: Core component managing hardware and system resources
- **GNU Utilities**: Command-line tools and utilities
- **System Libraries**: Shared code for applications
- **Package Manager**: Tool to install/manage software
- **Desktop Environment** (optional): Graphical interface

### Popular Distributions

```bash
# Debian-based (Ubuntu, Mint, Kali)
- User-friendly, large community
- APT package manager
- Great for beginners and web development

# Red Hat-based (Fedora, CentOS, RHEL)
- Enterprise-focused
- YUM/DNF package manager
- Common in corporate environments

# Arch-based (Arch, Manjaro)
- Rolling release, cutting-edge
- Pacman package manager
- For advanced users who want control
```

**Practical Example**: Check your distribution
```bash
# See your distribution information
cat /etc/os-release

# Output example:
# NAME="Ubuntu"
# VERSION="22.04.3 LTS (Jammy Jellyfish)"
# ID=ubuntu
# ID_LIKE=debian

# Check kernel version
uname -r
# Output: 5.15.0-91-generic
```

---

## Linux Architecture

Linux follows a layered architecture:

```
┌─────────────────────────────────────┐
│     User Applications               │  (Browser, VS Code, Node.js)
├─────────────────────────────────────┤
│     Shell (Bash, Zsh)               │  (Command interpreter)
├─────────────────────────────────────┤
│     System Libraries (glibc)        │  (C library, shared functions)
├─────────────────────────────────────┤
│     System Calls Interface          │  (API to kernel)
├─────────────────────────────────────┤
│     Linux Kernel                    │  (Core OS)
│  ┌─────────────────────────────┐   │
│  │ Process Management          │   │
│  │ Memory Management           │   │
│  │ File System                 │   │
│  │ Device Drivers              │   │
│  │ Networking                  │   │
│  └─────────────────────────────┘   │
├─────────────────────────────────────┤
│     Hardware                        │  (CPU, RAM, Disk, Network)
└─────────────────────────────────────┘
```

### The Kernel

The kernel is responsible for:
- **Process Management**: Creating, scheduling, terminating processes
- **Memory Management**: Allocating RAM, virtual memory, swap
- **File System**: Managing files and directories
- **Device Drivers**: Communicating with hardware
- **Networking**: TCP/IP stack, socket management

**Practical Example**: Explore kernel information
```bash
# View kernel messages
dmesg | less

# Check loaded kernel modules
lsmod

# View detailed hardware information
lshw -short

# See CPU information
cat /proc/cpuinfo

# View memory information
cat /proc/meminfo
```

---

## The Linux Filesystem

### Filesystem Hierarchy Standard (FHS)

Everything in Linux is a file or directory. The filesystem starts at `/` (root).

```
/                          Root directory
├── bin/                   Essential user binaries (ls, cp, cat)
├── boot/                  Boot loader files, kernel
├── dev/                   Device files (hard drives, terminals)
├── etc/                   Configuration files
│   ├── passwd             User account information
│   ├── group              Group information
│   ├── hosts              Static hostname resolution
│   └── nginx/             Nginx configuration
├── home/                  User home directories
│   └── username/          Individual user's home
├── lib/                   Shared libraries
├── media/                 Mount points for removable media
├── mnt/                   Temporary mount points
├── opt/                   Optional application packages
├── proc/                  Virtual filesystem (process info)
├── root/                  Root user's home directory
├── run/                   Runtime data (PIDs, sockets)
├── sbin/                  System binaries (root-only)
├── srv/                   Service data (web servers)
├── sys/                   Virtual filesystem (hardware info)
├── tmp/                   Temporary files (cleared on reboot)
├── usr/                   User programs and data
│   ├── bin/               User binaries
│   ├── lib/               Libraries for /usr/bin
│   ├── local/             Locally installed software
│   └── share/             Shared data
└── var/                   Variable data
    ├── log/               Log files
    ├── www/               Web server content
    └── tmp/               Temp files (preserved on reboot)
```

**Practical Examples**:

```bash
# Navigate the filesystem
cd /etc                    # Change to /etc
pwd                        # Print working directory
ls -lah                    # List all files with details

# Understanding paths
cd /var/log                # Absolute path
cd ../www                  # Relative path (up one, then www)
cd ~                       # Go to home directory
cd -                       # Go to previous directory

# Find files
find /etc -name "*.conf"   # Find all .conf files in /etc
locate nginx.conf          # Fast search using database
which node                 # Find location of node binary
whereis python3            # Find binary, source, man pages
```

### File Types

```bash
# List files with types
ls -l

# Output explanation:
# drwxr-xr-x  directory
# -rw-r--r--  regular file
# lrwxrwxrwx  symbolic link
# brw-rw----  block device
# crw-rw----  character device
# srwxrwxrwx  socket
# prw-r--r--  named pipe (FIFO)

# First character indicates type:
# d = directory
# - = regular file
# l = symbolic link
# b = block device (hard drives)
# c = character device (terminals)
# s = socket
# p = pipe
```

**Hands-on Example**:
```bash
# Create different file types
mkdir test_dir                        # Directory
touch test_file.txt                   # Regular file
ln -s test_file.txt link_file         # Symbolic link
mkfifo test_pipe                      # Named pipe

# Verify types
ls -l
# drwxr-xr-x  test_dir
# -rw-r--r--  test_file.txt
# lrwxrwxrwx  link_file -> test_file.txt
# prw-r--r--  test_pipe

# Everything is a file - even devices!
ls -l /dev/sda                        # Hard drive (block device)
ls -l /dev/tty                        # Terminal (character device)
```

### Inodes and Links

An **inode** stores metadata about a file (permissions, timestamps, location on disk) but not the filename.

```bash
# View inode numbers
ls -li

# Output:
# 123456 -rw-r--r--  1 user user  0 file.txt

# Inode contains:
# - File type and permissions
# - Owner and group
# - File size
# - Timestamps (access, modify, change)
# - Number of hard links
# - Pointers to data blocks
```

**Hard Links vs Symbolic Links**:

```bash
# Create a file
echo "Hello Linux" > original.txt

# Hard link (same inode, different name)
ln original.txt hardlink.txt

# Symbolic link (different inode, pointer)
ln -s original.txt symlink.txt

# Check inodes
ls -li
# 123456 -rw-r--r--  2 user user 12 original.txt
# 123456 -rw-r--r--  2 user user 12 hardlink.txt
# 789012 lrwxrwxrwx  1 user user 12 symlink.txt -> original.txt

# Hard link: Same inode number (123456), link count = 2
# Symlink: Different inode (789012), points to original

# Delete original
rm original.txt

# Hard link still works (data still exists)
cat hardlink.txt  # Output: Hello Linux

# Symlink broken (points to non-existent file)
cat symlink.txt   # Error: No such file or directory
```

---

## Processes and Process Management

A **process** is a running instance of a program. Each process has:
- **PID** (Process ID): Unique identifier
- **PPID** (Parent Process ID): ID of process that created it
- **UID**: User ID running the process
- **State**: Running, sleeping, stopped, zombie
- **Memory**: Allocated RAM
- **Priority**: Scheduling priority

### Process States

```
                ┌──────────┐
                │  Created │
                └────┬─────┘
                     ↓
                ┌──────────┐
           ┌───→│ Runnable │←───┐
           │    └────┬─────┘    │
           │         ↓           │
           │    ┌──────────┐    │
           │    │ Running  │────┘
           │    └────┬─────┘
           │         ↓
      ┌────┴────┬────┴────┬─────────┐
      ↓         ↓         ↓         ↓
┌──────────┐ ┌──────┐ ┌────────┐ ┌────────┐
│ Sleeping │ │ Stopped│ │ Zombie │ │ Dead   │
└──────────┘ └────────┘ └────────┘ └────────┘
```

**Practical Examples**:

```bash
# View all processes
ps aux
# a = all users, u = user-oriented, x = include background

# Better process viewer
top                        # Interactive, updates every 3s
htop                       # Enhanced version (install first)

# Process tree (show parent-child relationships)
pstree
pstree -p                  # Include PIDs

# Find specific processes
ps aux | grep nginx
pgrep -l nginx             # Shorter way

# View process details
ps -p 1234 -f              # Full details for PID 1234
cat /proc/1234/status      # All process information

# Background and foreground jobs
sleep 100 &                # Run in background
jobs                       # List background jobs
fg %1                      # Bring job 1 to foreground
Ctrl+Z                     # Suspend current job
bg %1                      # Resume job 1 in background

# Kill processes
kill 1234                  # Send SIGTERM (graceful)
kill -9 1234               # Send SIGKILL (force)
killall nginx              # Kill all nginx processes
pkill -f "node server.js"  # Kill by pattern

# Process priority (nice values: -20 to 19)
nice -n 10 ./script.sh     # Start with low priority
renice -n 5 -p 1234        # Change priority of running process
```

### Real-World Example: Node.js Process Management

```bash
# Start a Node.js server in background
node server.js &
# Output: [1] 5678

# Check it's running
ps aux | grep "node server.js"
netstat -tlnp | grep 5678

# Monitor resource usage
top -p 5678

# Gracefully stop
kill -SIGTERM 5678

# If it doesn't stop, force kill
kill -9 5678
```

---

## Users and Permissions

Linux is a multi-user system with granular permission control.

### Users and Groups

```bash
# View current user
whoami
id
# uid=1000(john) gid=1000(john) groups=1000(john),27(sudo)

# View all users
cat /etc/passwd
# Format: username:password:UID:GID:comment:home:shell
# john:x:1000:1000:John Doe:/home/john:/bin/bash

# Password hashes stored separately
cat /etc/shadow              # Requires sudo

# View groups
cat /etc/group
groups                       # Current user's groups
groups john                  # John's groups

# Add user
sudo useradd -m -s /bin/bash alice
sudo passwd alice

# Add to sudo group
sudo usermod -aG sudo alice

# Delete user
sudo userdel -r alice        # -r removes home directory
```

### File Permissions

```
-rwxr-xr--  1 john developers 4096 Dec 06 10:00 script.sh
 │││││││││  │  │       │
 │││││││││  │  │       └─ Group
 │││││││││  │  └───────── Owner
 │││││││││  └──────────── Link count
 ││││││││└─ Others: r (read)
 │││││││└── Others: - (no write)
 ││││││└─── Others: - (no execute)
 │││││└──── Group: r (read)
 ││││└───── Group: - (no write)
 │││└────── Group: x (execute)
 ││└─────── Owner: r (read)
 │└──────── Owner: w (write)
 └───────── Owner: x (execute)
```

**Permission Values**:
- **r (read)**: 4
- **w (write)**: 2
- **x (execute)**: 1

```bash
# Symbolic notation
chmod u+x script.sh          # Add execute for user (owner)
chmod g-w file.txt           # Remove write for group
chmod o=r file.txt           # Set others to read-only
chmod a+r file.txt           # Add read for all (user, group, others)

# Numeric notation (octal)
chmod 755 script.sh          # rwxr-xr-x
chmod 644 file.txt           # rw-r--r--
chmod 600 private.key        # rw------- (private)
chmod 777 danger.sh          # rwxrwxrwx (dangerous!)

# Common permissions:
# 755 - Executable scripts, directories
# 644 - Regular files
# 600 - Private files (SSH keys, passwords)
# 700 - Private directories
# 664 - Shared files (group write)

# Change owner
sudo chown alice file.txt
sudo chown alice:developers file.txt
sudo chown -R alice:developers /var/www/project

# Change group only
sudo chgrp developers file.txt
```

### Special Permissions

```bash
# SetUID (SUID) - Run as file owner
chmod u+s /usr/bin/passwd
ls -l /usr/bin/passwd
# -rwsr-xr-x  (notice 's' instead of 'x')

# SetGID (SGID) - Run as group owner, or inherit group on new files
chmod g+s /shared/project
# -rwxr-sr-x

# Sticky Bit - Only owner can delete files
chmod +t /tmp
ls -ld /tmp
# drwxrwxrwt  (notice 't' at end)

# Numeric notation:
# 4755 - SUID
# 2755 - SGID
# 1755 - Sticky
```

**React Developer Example**:
```bash
# Set up project permissions
mkdir -p ~/projects/react-app
cd ~/projects/react-app

# Initialize React app
npx create-react-app .

# Set proper permissions
chmod 644 package.json          # Read/write for owner
chmod 755 node_modules/.bin/*   # Executables
chmod 600 .env                  # Private environment variables

# For deployment
sudo chown -R www-data:www-data /var/www/react-app
sudo chmod -R 755 /var/www/react-app
sudo chmod -R 644 /var/www/react-app/build/*
```

---

## Package Management

Package managers handle software installation, updates, and dependencies.

### APT (Debian/Ubuntu)

```bash
# Update package database
sudo apt update

# Upgrade all packages
sudo apt upgrade
sudo apt full-upgrade           # Also removes/adds packages

# Install package
sudo apt install nginx
sudo apt install -y nginx       # Auto-confirm

# Install specific version
sudo apt install nginx=1.18.0-0ubuntu1

# Search packages
apt search nginx
apt-cache search nginx

# Show package information
apt show nginx
apt-cache policy nginx          # Available versions

# Remove package
sudo apt remove nginx           # Keep config files
sudo apt purge nginx            # Remove config too
sudo apt autoremove             # Remove unused dependencies

# List installed packages
apt list --installed
dpkg -l

# Check which package provides a file
dpkg -S /usr/bin/nginx
```

### Managing Node.js and npm

```bash
# Install Node.js via package manager
sudo apt install nodejs npm

# Better: Use nvm (Node Version Manager)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Install Node versions
nvm install 18
nvm install 20
nvm use 18

# List installed versions
nvm list

# Install global npm packages
npm install -g typescript
npm install -g pm2

# View global packages
npm list -g --depth=0

# Global package location
npm root -g
# Usually: /usr/local/lib/node_modules

# Local project packages
cd ~/project
npm install
# Installs to: ./node_modules
```

---

## System Services

Modern Linux uses **systemd** to manage services (daemons).

### Systemd Basics

```bash
# Service status
systemctl status nginx
systemctl is-active nginx
systemctl is-enabled nginx

# Start/stop/restart service
sudo systemctl start nginx
sudo systemctl stop nginx
sudo systemctl restart nginx
sudo systemctl reload nginx      # Reload config without restart

# Enable/disable (start on boot)
sudo systemctl enable nginx
sudo systemctl disable nginx

# View all services
systemctl list-units --type=service
systemctl list-units --type=service --state=running

# View service logs
journalctl -u nginx
journalctl -u nginx -f           # Follow (like tail -f)
journalctl -u nginx --since today
journalctl -u nginx --since "2024-12-01" --until "2024-12-06"

# View boot messages
journalctl -b
journalctl -b -1                 # Previous boot
```

### Creating a Custom Service

**Example: Node.js application as a service**

```bash
# Create service file
sudo nano /etc/systemd/system/myapp.service
```

```ini
[Unit]
Description=My React Backend API
After=network.target

[Service]
Type=simple
User=john
WorkingDirectory=/home/john/myapp
Environment="NODE_ENV=production"
Environment="PORT=3000"
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Reload systemd
sudo systemctl daemon-reload

# Start and enable service
sudo systemctl start myapp
sudo systemctl enable myapp

# Check status
systemctl status myapp

# View logs
journalctl -u myapp -f
```

---

## Practical Lab: Setting Up a React Development Environment

Let's put everything together!

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install prerequisites
sudo apt install -y curl git build-essential

# 3. Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc

# 4. Install Node.js
nvm install 20
nvm use 20
node --version

# 5. Create project directory
mkdir -p ~/projects/my-react-app
cd ~/projects/my-react-app

# 6. Initialize React app
npx create-react-app .

# 7. Set proper permissions
chmod 755 ~/projects
chmod 755 ~/projects/my-react-app
chmod 644 package.json

# 8. Create .env file (never commit!)
echo "REACT_APP_API_URL=http://localhost:3001" > .env
chmod 600 .env

# 9. Install dependencies
npm install

# 10. Start development server
npm start

# 11. In another terminal, check the process
ps aux | grep "node"
netstat -tlnp | grep 3000

# 12. Build for production
npm run build

# 13. Check build output
ls -lh build/
du -sh build/
```

---

## Key Takeaways

1. **Everything is a file** in Linux - devices, processes, directories
2. **Filesystem hierarchy** is standardized and logical
3. **Permissions** control access at user/group/other levels
4. **Processes** are managed by the kernel with clear lifecycle
5. **Package managers** handle dependencies and updates
6. **Systemd** manages services and system initialization

---

## Next Steps

- Practice these commands daily
- Experiment in a safe VM environment
- Read man pages: `man ls`, `man chmod`, `man systemd`
- Move on to **Networking Concepts** and **Shell Scripting**
- Build small automation scripts
- Set up a personal Linux server

**Remember**: Understanding these fundamentals is crucial for DevOps, cloud computing, and cybersecurity work!
