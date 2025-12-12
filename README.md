# Complete Ethical Hacking Course

![Ethical Hacking](https://img.shields.io/badge/Ethical-Hacking-red)
![Linux](https://img.shields.io/badge/Platform-Linux-blue)
![License](https://img.shields.io/badge/License-Educational-green)

A comprehensive, hands-on ethical hacking course covering everything from Linux fundamentals to advanced penetration testing techniques.

---

## 🎯 What You'll Learn

This complete ethical hacking curriculum includes:

- ✅ **Linux Fundamentals** - Master the command line and system administration
- ✅ **Network Security** - Understand protocols, scanning, and MITM attacks
- ✅ **Web Application Hacking** - SQL injection, XSS, and OWASP Top 10
- ✅ **Cryptography** - Password cracking and encryption analysis
- ✅ **Wireless Security** - WiFi cracking and wireless attacks
- ✅ **Exploitation** - Metasploit, buffer overflows, and privilege escalation
- ✅ **Post-Exploitation** - Persistence, lateral movement, and data exfiltration
- ✅ **Social Engineering** - Phishing, OSINT, and human hacking
- ✅ **CTF Challenges** - Real-world practice scenarios
- ✅ **Capstone Projects** - Professional penetration testing simulations

---

## 📚 Course Structure

### 10 Comprehensive Modules:

| Module | Topic | Status | Scripts |
|--------|-------|--------|---------|
| 01 | [Linux Basics](./01-linux-basics/) | ✅ Complete | 3 scripts |
| 02 | [Networking](./02-networking/) | 📝 Framework | TBD |
| 03 | [Web Security](./03-web-security/) | ✅ Lessons | 1 script |
| 04 | [Cryptography](./04-cryptography/) | 📝 Framework | TBD |
| 05 | [Wireless Security](./05-wireless-security/) | 📝 Framework | TBD |
| 06 | [Exploitation](./06-exploitation/) | 📝 Framework | TBD |
| 07 | [Post-Exploitation](./07-post-exploitation/) | 📝 Framework | TBD |
| 08 | [Social Engineering](./08-social-engineering/) | 📝 Framework | TBD |
| 09 | [CTF Practice](./09-ctf-practice/) | 📝 Framework | TBD |
| 10 | [Capstone Projects](./10-capstone-projects/) | 📝 Framework | TBD |

**Total:** 200+ hours of content

---

## 🚀 Quick Start

### 1. Prerequisites

- **Kali Linux** (recommended) or any Linux distribution
- Basic computer skills
- **Legal authorization** for any testing activities

### 2. Setup

```bash
# Clone this repository (if not already done)
git clone https://github.com/yourusername/ethical-hacking-course.git
cd ethical-hacking-course

# Configure vim (already done if you followed initial setup)
cp vimrc ~/.vimrc

# Make scripts executable
chmod +x */scripts/*.sh
```

### 3. Start Learning

```bash
# Read the full course index
cat COURSE-INDEX.md

# Start with Module 1
cd 01-linux-basics
cat README.md

# Run your first reconnaissance script
./scripts/system_recon.sh
```

### 4. Track Your Progress

```bash
# Open the progress tracker
vim PROGRESS-TRACKER.md

# Mark lessons as you complete them
```

---

## 📖 Documentation

- **[📋 Course Index](./COURSE-INDEX.md)** - Complete course overview
- **[📊 Progress Tracker](./PROGRESS-TRACKER.md)** - Track your learning journey
- **[📚 Module READMEs](./01-linux-basics/README.md)** - Detailed module information

### Additional Resources:
- **[🐧 Linux Fundamentals](./LINUX-FUNDAMENTALS-TUTORIAL.md)**
- **[🔒 Security Concepts](./SECURITY-CONCEPTS-TUTORIAL.md)**
- **[🌐 Networking Concepts](./NETWORKING-CONCEPTS-TUTORIAL.md)**
- **[💻 Shell Scripting](./SHELL-SCRIPTING-TUTORIAL.md)**
- **[🔐 DevSecOps](./DEVSECOPS-TUTORIAL.md)**
- **[🗺️ Learning Roadmap](./ROADMAP.md)**

---

## 🛠️ Practice Scripts

### Module 1: Linux Basics

**System Reconnaissance**
```bash
cd 01-linux-basics/scripts
./system_recon.sh
```
Performs comprehensive system enumeration for penetration testing.

**User Enumeration & Privilege Escalation**
```bash
./user_enum.sh
```
Identifies privilege escalation vectors and security misconfigurations.

**Network Scanner**
```bash
./network_scanner.sh
# or
./network_scanner.sh 192.168.1.10
```
Pure bash network reconnaissance tool.

### Module 3: Web Security

**Web Crawler & Enumerator**
```bash
cd 03-web-security/scripts
./web_crawler.sh -u http://example.com -d 2
```
Discovers web pages, forms, and parameters for security testing.

---

## 📝 Learning Path

### For Complete Beginners:

**Phase 1: Foundations (8-12 weeks)**
1. Module 1: Linux Basics
2. Module 2: Networking
3. Practice on TryHackMe "Complete Beginner" path

**Phase 2: Core Skills (12-16 weeks)**
4. Module 3: Web Application Security
5. Module 4: Cryptography
6. Module 5: Wireless Security
7. Practice: DVWA, WebGoat, Juice Shop

**Phase 3: Advanced Techniques (12-16 weeks)**
8. Module 6: Exploitation
9. Module 7: Post-Exploitation
10. Module 8: Social Engineering

**Phase 4: Mastery (Ongoing)**
11. Module 9: CTF Practice
12. Module 10: Capstone Projects
13. Prepare for CEH/OSCP certification

### For IT Professionals:

**Fast Track (3-6 months)**
- Quick review of Modules 1-2
- Deep dive into Modules 3, 6, 7
- Extensive CTF practice
- Prepare for OSCP

---

## 🎓 Certifications Preparation

This course prepares you for:

- **CEH** (Certified Ethical Hacker)
- **OSCP** (Offensive Security Certified Professional)
- **eWPT** (Web Application Penetration Tester)
- **PNPT** (Practical Network Penetration Tester)
- **CompTIA Security+**

---

## 🏆 Practice Platforms

### Recommended for This Course:

**Beginner-Friendly:**
- [TryHackMe](https://tryhackme.com) - Guided learning paths
- [OverTheWire](https://overthewire.org) - Terminal skills
- [PentesterLab](https://pentesterlab.com) - Web security basics

**Intermediate:**
- [HackTheBox](https://hackthebox.eu) - Realistic machines
- [VulnHub](https://vulnhub.com) - Downloadable VMs
- [PicoCTF](https://picoctf.org) - CTF challenges

**Advanced:**
- [Offensive Security Labs](https://offensive-security.com) - OSCP prep
- [SANS Cyber Ranges](https://sans.org) - Professional training

**Vulnerable Applications:**
- DVWA (Damn Vulnerable Web App)
- bWAPP
- WebGoat
- Juice Shop
- Mutillidae

---

## ⚖️ Legal & Ethical Guidelines

### ⚠️ CRITICAL - READ BEFORE PROCEEDING

**Legal Testing Only:**
- ✅ Your own systems and virtual machines
- ✅ Authorized penetration testing engagements
- ✅ Bug bounty programs with proper scope
- ✅ Educational platforms (TryHackMe, HTB, etc.)
- ✅ Deliberately vulnerable applications (DVWA, etc.)

**Illegal Testing:**
- ❌ Systems you don't own without written permission
- ❌ Company networks without authorization
- ❌ Any system where you lack explicit consent
- ❌ Testing beyond authorized scope

**Consequences of Illegal Hacking:**
- Criminal prosecution
- Imprisonment
- Fines
- Permanent criminal record
- Career destruction

**This course is for ETHICAL hacking education only. Always obtain proper authorization before testing any system.**

---

## 🤝 Community & Support

### Getting Help:

1. **Review the lesson materials** - Most answers are in the documentation
2. **Check the scripts** - Study the code to understand techniques
3. **Search online** - Many topics have extensive documentation
4. **Join communities:**
   - Reddit: r/HowToHack, r/AskNetsec, r/cybersecurity
   - Discord: TryHackMe, HackTheBox communities
   - Forums: Null Byte, Security Stack Exchange

### Best Practices:

- Don't ask for "hacking someone's account" - it's illegal
- Show your research and what you've tried
- Be specific about errors and issues
- Respect community guidelines

---

## 🔧 Tools Reference

### Essential Tools (Pre-installed on Kali):

**Reconnaissance:**
- nmap, masscan, autorecon
- gobuster, dirb, ffuf
- whois, dig, dnsenum, theHarvester

**Web Application:**
- Burp Suite, OWASP ZAP
- sqlmap, wpscan, nikto
- wfuzz, ffuf

**Exploitation:**
- Metasploit Framework
- searchsploit (Exploit-DB)
- msfvenom

**Password Attacks:**
- John the Ripper
- Hashcat
- Hydra, Medusa

**Wireless:**
- Aircrack-ng
- Wifite
- Reaver

**Post-Exploitation:**
- Mimikatz
- BloodHound
- Empire, Covenant

---

## 📊 Progress Tracking

Use the built-in progress tracker to monitor your journey:

```bash
vim PROGRESS-TRACKER.md
```

**Track:**
- ✅ Module completion
- ✅ Lesson checkboxes
- ✅ Script execution
- ✅ Skills acquired
- ✅ Study hours
- ✅ Certification goals

---

## 🌟 What Makes This Course Unique

1. **Completely Free** - No paywalls or hidden costs
2. **Hands-On** - Every module includes practice scripts
3. **Comprehensive** - 10 modules covering all aspects
4. **Self-Paced** - Learn at your own speed
5. **Practical** - Real-world applicable skills
6. **Up-to-Date** - Current techniques and tools
7. **Beginner-Friendly** - Starts from basics
8. **Certification-Ready** - Prepares you for CEH/OSCP

---

## 📈 Course Roadmap

### Completed:
- ✅ Linux Basics module (lessons + scripts)
- ✅ Web Security fundamentals (SQL injection lesson)
- ✅ Progress tracking system
- ✅ Practice scripts (recon, enum, scanning, web)

### In Development:
- 🔄 Additional web security lessons (XSS, CSRF, etc.)
- 🔄 Networking module content
- 🔄 Cryptography module content
- 🔄 CTF challenges

### Planned:
- 📅 Video tutorials
- 📅 Lab environment setup guides
- 📅 Additional practice scripts
- 📅 Community challenges

---

## 📄 License

**Educational Use Only**

This course is provided for educational purposes to help individuals learn ethical hacking and cybersecurity. All techniques taught must only be used legally and ethically.

**Disclaimer:** The creators of this course are not responsible for any misuse of the information provided. Students are responsible for ensuring they comply with all applicable laws and regulations.

---

## 🙏 Acknowledgments

This course builds upon knowledge from the cybersecurity community, including:
- OWASP Project
- Offensive Security
- HackerOne
- TryHackMe
- HackTheBox
- Security researchers worldwide

---

## 📞 Get Started Now!

```bash
# Start your ethical hacking journey
cd 01-linux-basics
cat README.md

# Run your first script
./scripts/system_recon.sh

# Begin learning!
```

**Remember: With great power comes great responsibility. Always hack ethically!**

---

**Happy Hacking! 🎉**
