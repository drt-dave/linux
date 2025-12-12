[#](#) Lesson 1.1: Linux File System & Navigation

## Objective
Master the Linux file system structure and learn essential navigation commands critical for penetration testing and system reconnaissance.

---

## The Linux File System Hierarchy

  ```
  /           - Root directory (everything starts here)
  /bin        - Essential user binaries (commands like ls, cp, cat)
/sbin       - System binaries (admin commands)
  /etc        - Configuration files
  /home       - User home directories
  /root       - Root user's home directory
  /var        - Variable data (logs, databases, web content)
/tmp        - Temporary files (world-writable, often exploitable)
  /usr        - User programs and data
  /opt        - Optional software packages
  /dev        - Device files (hardware interfaces)
/proc       - Process and kernel information (virtual filesystem)
  /sys        - System and kernel information
  ```

### Why This Matters for Hacking:
  - **/etc** - Contains password files, service configs, potential credentials
  - **/var/log** - Log files reveal system activity, user behavior
  - **/tmp** - World-writable, useful for uploading exploits
  - **/proc** - Process information, useful for enumeration
  - **/home** - User files, SSH keys, credentials
  - **/root** - High-value target containing root user's files

  ---

## Essential Navigation Commands

### 1. pwd - Print Working Directory
  ```bash
  pwd
  ```
  Shows your current location in the file system.

  **Hacking Use Case:** Orient yourself after initial shell access

  ---

### 2. ls - List Directory Contents

#### Basic Usage:
  ```bash
  ls              # List files
  ls -l           # Long format (permissions, owner, size, date)
ls -la          # Include hidden files (files starting with .)
  ls -lh          # Human-readable file sizes
  ls -lt          # Sort by modification time
  ls -lR          # Recursive listing
  ```

#### Advanced Usage for Reconnaissance:
  ```bash
  ls -la /etc/    # List all config files
  ls -la /home/   # Enumerate user directories
  ls -la ~/.ssh/  # Look for SSH keys
  ls -lt /var/log/# Recent log files
find / -perm -4000 2>/dev/null  # Find SUID binaries (privilege escalation)
  ```

  **Hacking Use Case:** Enumerate system, find sensitive files, discover attack vectors

  ---

### 3. cd - Change Directory

  ```bash
  cd /etc                 # Absolute path
  cd ../                  # Go up one directory
  cd ../../               # Go up two directories
  cd ~                    # Go to home directory
  cd -                    # Go to previous directory
  cd /var/www/html        # Navigate to web root
  ```

  **Hacking Use Case:** Navigate to target directories quickly

  ---

### 4. File Operations Critical for Hacking

#### cat - Concatenate and Display Files
  ```bash
  cat /etc/passwd          # View user accounts
cat /etc/shadow          # View password hashes (if you have access)
  cat /var/log/auth.log    # View authentication logs
  cat ~/.bash_history      # View command history
  ```

#### head & tail - View Beginning or End of Files
  ```bash
  head -n 20 /var/log/syslog      # First 20 lines
  tail -n 50 /var/log/apache2/access.log  # Last 50 lines
  tail -f /var/log/auth.log       # Follow log in real-time
  ```

#### more & less - Page Through Files
  ```bash
less /var/log/syslog    # Better than more (scroll up/down)
  ```

  **Pro Tip:** In `less`, press `/` to search, `n` for next match

  ---

### 5. Finding Files

#### find - The Swiss Army Knife
  ```bash
# Find SUID files (privilege escalation goldmine)
  find / -perm -4000 -type f 2>/dev/null

# Find files owned by specific user
  find / -user admin 2>/dev/null

# Find writable files
  find / -writable -type f 2>/dev/null

# Find files modified in last 24 hours
  find /etc -mtime -1

# Find files containing passwords
  find / -name "*password*" 2>/dev/null
  find / -name "*.conf" 2>/dev/null | xargs grep -i "password"

# Find backup files
  find / -name "*.bak" -o -name "*.backup" 2>/dev/null
  ```

#### locate - Fast File Search (uses database)
  ```bash
  updatedb                # Update the database first
  locate password         # Find files with "password" in name
  locate .ssh             # Find SSH directories
  ```

#### which - Find Command Locations
  ```bash
  which python            # Find Python binary
  which gcc               # Check if compiler exists
  which nc                # Check for netcat
  ```

  ---

### 6. File Information

#### file - Determine File Type
  ```bash
  file suspicious_binary
  file image.jpg
  file /bin/bash
  ```

  **Hacking Use Case:** Verify file types, detect hidden executables

#### stat - Detailed File Information
  ```bash
  stat /etc/passwd        # Timestamps, permissions, inode
  ```

  ---

## Permissions & Ownership

### Understanding Permissions

  ```
  -rwxr-xr-x 1 root root 4096 Jan 1 12:00 file.sh
  │└┬┘└┬┘└┬┘   │    │
  │ │  │  │    │    └─ Group
  │ │  │  │    └─ Owner
  │ │  │  └─ Others permissions (r-x = read, execute)
  │ │  └─ Group permissions (r-x)
  │ └─ Owner permissions (rwx = read, write, execute)
└─ File type (- = regular file, d = directory, l = link)
  ```

### Numeric Permissions:
  - **r (read) = 4**
  - **w (write) = 2**
  - **x (execute) = 1**

  ```bash
  chmod 755 script.sh     # rwxr-xr-x
  chmod 644 file.txt      # rw-r--r--
  chmod 600 private.key   # rw-------
  chmod +x script.sh      # Add execute permission
  ```

### Special Permissions (Critical for Privilege Escalation!):

#### SUID (Set User ID) - 4000
  ```bash
  -rwsr-xr-x  # The 's' in owner execute position
  ```
  **Hacking Goldmine:** File executes with owner's privileges!
  ```bash
  find / -perm -4000 2>/dev/null  # Find SUID binaries
  ```

#### SGID (Set Group ID) - 2000
  ```bash
  -rwxr-sr-x  # The 's' in group execute position
  ```

#### Sticky Bit - 1000
  ```bash
  drwxrwxrwt  # The 't' in others execute position
  ```
  Example: /tmp (anyone can write, but only owner can delete their files)

  ---

## Hands-On Exercises

### Exercise 1: File System Reconnaissance
  ```bash
# Navigate to root and examine the structure
  cd /
  ls -la

# Find all SUID binaries
  find / -perm -4000 -type f 2>/dev/null

# List all users
  cat /etc/passwd | cut -d: -f1

# Find writable directories
  find / -type d -writable 2>/dev/null
  ```

### Exercise 2: Find Sensitive Information
  ```bash
# Search for password files
  find / -name "*password*" 2>/dev/null

# Search for SSH keys
  find / -name "id_rsa" 2>/dev/null

# Search for database files
  find / -name "*.db" -o -name "*.sqlite" 2>/dev/null

# Search configuration files for passwords
  grep -r "password" /etc/ 2>/dev/null
  ```

### Exercise 3: Permission Analysis
  ```bash
# Check permissions on sensitive files
  ls -la /etc/passwd
  ls -la /etc/shadow
  ls -la /etc/sudoers

# Find files you can write to
  find /etc -writable 2>/dev/null
  ```

  ---

## Pro Tips for Ethical Hackers

  1. **Always redirect errors:** Use `2>/dev/null` to hide "Permission denied" messages
  ```bash
  find / -name "*.conf" 2>/dev/null
  ```

  2. **Combine commands with pipes:**
  ```bash
  cat /etc/passwd | grep bash | cut -d: -f1
  ```

  3. **Use wildcards effectively:**
  ```bash
  ls /var/log/*.log
			   find / -name "*.conf"
			   ```

			   4. **History is golden:**
			   ```bash
			   cat ~/.bash_history
			   cat /root/.bash_history  # If you have access
			   ```

			   5. **Check for backups:**
			   ```bash
			   ls -la /var/backups/
			   find / -name "*.bak" 2>/dev/null
			   ```

			   ---

## Common Attack Vectors

### 1. World-Writable Directories
```bash
find / -type d -perm -0002 2>/dev/null
```
Use these to upload and execute payloads

### 2. Readable Sensitive Files
```bash
cat /etc/passwd     # User enumeration
cat /etc/shadow     # Password hashes (if readable)
cat /root/.ssh/id_rsa  # SSH private keys
```

### 3. Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.*
```

### 4. Configuration Files
```bash
find /etc -name "*.conf" 2>/dev/null | xargs grep -i "password"
find / -name "config.php" 2>/dev/null
```

---

## Practice Challenge

Create a script that performs initial reconnaissance on a Linux system:
- Enumerate users
- Find SUID binaries
- List writable directories
- Search for credentials in common locations
- Check for interesting cron jobs

Solution in: `01-linux-basics/scripts/system_recon.sh`

---

## Key Takeaways

1. The file system structure reveals critical attack surfaces
2. SUID binaries are privilege escalation goldmines
3. /tmp, /var, /etc are high-value targets
4. Hidden files (starting with .) often contain credentials
5. Proper navigation and file searching are essential pentesting skills

---

## Next Lesson
  **Lesson 1.2: User & Permission Management** - Learn how to enumerate users, manage permissions, and exploit misconfigurations.
