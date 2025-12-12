# Quick Start Guide - Ethical Hacking Course

## Welcome! 🎉

This guide will help you start your ethical hacking journey in under 10 minutes.

---

## ✅ Step 1: Verify Setup

```bash
# Check you're in the course directory
pwd
# Should show: /root/linux (or similar)

# Check vim is configured
cat ~/.vimrc | head -5
# Should show vim configuration

# Verify course structure
ls -la
# Should see 10 module directories (01-linux-basics through 10-capstone-projects)
```

---

## ✅ Step 2: Understand the Structure

```
linux/
├── README.md                    # Main course overview
├── COURSE-INDEX.md              # Detailed module breakdown
├── PROGRESS-TRACKER.md          # Track your progress
├── QUICK-START-GUIDE.md         # This file!
│
├── 01-linux-basics/             # Module 1: Linux Fundamentals
│   ├── README.md
│   ├── lessons/                 # Lesson files
│   │   ├── 01-file-system-navigation.md
│   │   └── 02-user-permission-management.md
│   ├── scripts/                 # Practice scripts
│   │   ├── system_recon.sh
│   │   ├── user_enum.sh
│   │   └── network_scanner.sh
│   └── exercises/               # Hands-on exercises
│
├── 02-networking/               # Module 2: Networking
├── 03-web-security/             # Module 3: Web App Security
│   ├── lessons/
│   │   └── 01-sql-injection.md  # SQL injection tutorial
│   └── scripts/
│       └── web_crawler.sh       # Web enumeration tool
│
├── 04-cryptography/             # Module 4: Crypto & Password Cracking
├── 05-wireless-security/        # Module 5: WiFi Hacking
├── 06-exploitation/             # Module 6: Exploitation
├── 07-post-exploitation/        # Module 7: Post-Exploitation
├── 08-social-engineering/       # Module 8: Social Engineering
├── 09-ctf-practice/             # Module 9: CTF Challenges
└── 10-capstone-projects/        # Module 10: Final Projects
```

---

## ✅ Step 3: Start Module 1

### Read the Introduction

```bash
cd 01-linux-basics
cat README.md
```

### Study the First Lesson

```bash
cd lessons
cat 01-file-system-navigation.md
# Or use vim for better navigation:
vim 01-file-system-navigation.md
```

**Vim Quick Commands:**
- `j` / `k` - Scroll down/up
- `Space` - Page down
- `b` - Page up
- `/search` - Search for "search"
- `q` - Quit (type `:q`)

---

## ✅ Step 4: Run Your First Script

### System Reconnaissance

```bash
cd ../scripts

# Run the system reconnaissance script
./system_recon.sh
```

**What it does:**
- Enumerates system information
- Lists all users
- Finds SUID binaries (privilege escalation)
- Searches for credentials
- Analyzes network configuration
- Checks running processes

**Output:** Creates a timestamped directory with results

```bash
# View the results
ls -la recon_*
cd recon_*/
cat SUMMARY.txt
```

---

## ✅ Step 5: Practice User Enumeration

```bash
# Run the user enumeration script
./user_enum.sh
```

**What to look for:**
- Current user privileges
- Sudo permissions (NOPASSWD = easy escalation!)
- Dangerous group memberships (docker, lxd)
- SUID binaries (especially unusual ones)
- Readable /etc/shadow (jackpot!)

---

## ✅ Step 6: Track Your Progress

```bash
cd ../..  # Back to main directory

# Open the progress tracker
vim PROGRESS-TRACKER.md
```

**Mark what you've completed:**
- [x] Lesson 1.1 - File System & Navigation
- [x] Executed system_recon.sh
- [x] Executed user_enum.sh

---

## 🎯 Your First Week Plan

### Day 1-2: Linux Basics
- Read `01-file-system-navigation.md`
- Run `system_recon.sh` on your system
- Practice Linux commands
- Complete exercises in the lesson

### Day 3-4: User & Permissions
- Read `02-user-permission-management.md`
- Run `user_enum.sh`
- Practice finding SUID binaries
- Try to identify privilege escalation vectors

### Day 5-6: Network Scanning
- Run `network_scanner.sh`
- Scan your local network (if authorized!)
- Learn about common ports and services
- Practice with nmap (if installed)

### Day 7: Review & Practice
- Review all lessons
- Re-run scripts and understand output
- Try TryHackMe "Linux Fundamentals" rooms
- Update your progress tracker

---

## 🛠️ Practice Environment Setup

### Option 1: Use Your Kali Linux (Safest)

Already set up! Just practice on your own system.

### Option 2: Set Up Virtual Machines

```bash
# Install VirtualBox or VMware
# Download vulnerable VMs from VulnHub:
# - Metasploitable 2
# - DVWA
# - Basic Pentesting 1
```

### Option 3: Online Platforms (Recommended for Beginners)

**TryHackMe (Best for Beginners):**
1. Sign up at https://tryhackme.com
2. Start "Complete Beginner" path
3. Practice what you learn here

**HackTheBox (More Advanced):**
1. Sign up at https://hackthebox.eu
2. Start with "Starting Point" machines
3. Practice exploitation techniques

---

## 📚 Essential Commands Reference

### Navigation
```bash
pwd                    # Where am I?
ls -la                 # List all files
cd /path/to/dir        # Change directory
cd ~                   # Go home
cd -                   # Go back
```

### File Operations
```bash
cat file.txt           # View file
less file.txt          # Page through file
head -n 20 file.txt    # First 20 lines
tail -f /var/log/syslog # Follow log file
find / -name "*.conf"  # Find files
```

### User Information
```bash
whoami                 # Current user
id                     # User ID and groups
sudo -l                # Sudo privileges
cat /etc/passwd        # All users
```

### Network
```bash
ip addr                # IP addresses
ss -tulpn              # Listening ports
ping 192.168.1.1       # Test connectivity
```

### Privilege Escalation Checks
```bash
find / -perm -4000 2>/dev/null    # SUID binaries
sudo -l                            # Sudo rights
groups                             # Group membership
getcap -r / 2>/dev/null           # Capabilities
```

---

## 🎓 Learning Tips

### 1. **Hands-On is Key**
- Don't just read - DO
- Run every command
- Experiment safely
- Break things (in VMs!)

### 2. **Document Everything**
- Keep notes on what works
- Save useful commands
- Create your own cheat sheets
- Screenshot important findings

### 3. **Practice Daily**
- Even 30 minutes daily is valuable
- Consistency beats intensity
- Review previous lessons regularly

### 4. **Join Communities**
- Ask questions (after researching!)
- Help others when you can
- Share your learnings
- Stay motivated

### 5. **Stay Legal**
- Only test authorized systems
- Use practice platforms
- Get written permission
- When in doubt, don't!

---

## 🚨 Common Beginner Mistakes to Avoid

### ❌ Don't:
1. Test systems without authorization
2. Skip the basics (they're crucial!)
3. Just run tools without understanding them
4. Give up when stuck
5. Forget to take breaks

### ✅ Do:
1. Practice in authorized environments
2. Master fundamentals first
3. Understand the "why" behind techniques
4. Research errors and issues
5. Take care of your health

---

## 🔥 Quick Challenges (Try These Now!)

### Challenge 1: System Enumeration
```bash
# How many users have bash shells?
cat /etc/passwd | grep bash | wc -l

# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# What services are listening?
ss -tulpn
```

### Challenge 2: File Hunting
```bash
# Find files modified in last 24 hours
find /etc -mtime -1 2>/dev/null

# Search for passwords in configs
grep -r "password" /etc 2>/dev/null | head

# Find writable directories
find / -writable -type d 2>/dev/null | head -10
```

### Challenge 3: Script Analysis
```bash
# Open and read the system_recon.sh script
cd 01-linux-basics/scripts
cat system_recon.sh

# Understand what each section does
# Can you modify it to add a new check?
```

---

## 📖 Recommended Reading Order

1. **linux/README.md** - Course overview
2. **COURSE-INDEX.md** - Detailed module breakdown
3. **PROGRESS-TRACKER.md** - Set up your tracker
4. **01-linux-basics/README.md** - Module 1 intro
5. **01-linux-basics/lessons/01-file-system-navigation.md** - First lesson
6. Start practicing!

---

## 🎯 Next Steps After This Guide

1. ✅ Complete Module 1 (1-2 weeks)
2. ✅ Move to Module 2: Networking
3. ✅ Practice on TryHackMe simultaneously
4. ✅ Join cybersecurity communities
5. ✅ Set long-term certification goals (CEH, OSCP)

---

## 💡 Remember

> "The only way to learn hacking is by hacking (legally!)"

**You don't need to be a genius. You need:**
- Curiosity
- Persistence
- Ethics
- Practice

---

## 🆘 Need Help?

### Course Issues:
1. Re-read the lesson material
2. Check the README files
3. Review script comments
4. Search online for specific errors

### Learning Struggles:
1. Slow down - it's not a race
2. Go back to basics if needed
3. Take breaks
4. Join TryHackMe for guided learning

### Legal Questions:
- If you're not sure if something is legal: **DON'T DO IT**
- Get written authorization
- Stick to authorized platforms

---

## 🎉 You're Ready!

You now have everything you need to start your ethical hacking journey.

**Your first action:**
```bash
cd 01-linux-basics/lessons
vim 01-file-system-navigation.md
```

**Happy hacking! Remember: Stay ethical, stay legal, stay curious!**

---

**Course Version:** 1.0
**Last Updated:** December 2025
