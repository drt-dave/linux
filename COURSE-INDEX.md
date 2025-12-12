# Complete Ethical Hacking Course

**Course Version:** 1.0
**Language:** English
**Last Updated:** December 2025

---

## Course Description

This comprehensive, hands-on ethical hacking course takes you from Linux fundamentals to advanced penetration testing techniques. Designed for aspiring security professionals, each module includes detailed lessons, practical scripts, and real-world exercises.

**Prerequisites:**
- Basic computer literacy
- Willingness to learn
- Legal authorization for any testing activities

**Duration:** Self-paced (estimated 200-300 hours for full mastery)

---

## Course Structure

### 📚 Module 1: Linux Basics for Hacking
**Directory:** `[01-linux-basics/](01-linux-basics/)`
**Status:** ✅ Complete with scripts

Master the Linux command line and system administration skills essential for ethical hacking.

**Topics:**
- File system navigation and reconnaissance
- User and permission management
- Process management and monitoring
- Network configuration
- Bash scripting for automation
- Privilege escalation techniques

**Practice Scripts:**
- `system_recon.sh` - Comprehensive system enumeration
- `user_enum.sh` - Privilege escalation checker
- `network_scanner.sh` - Pure bash network scanner

**Learning Outcomes:**
- Navigate Linux systems with confidence
- Enumerate users and find privilege escalation vectors
- Automate reconnaissance tasks
- Understand SUID/SGID exploitation

[📖 Start Module 1](./01-linux-basics/README.md)

---

### 🌐 Module 2: Networking for Ethical Hacking
**Directory:** `02-networking/`

Deep dive into networking concepts, protocols, and attack techniques.

**Topics:**
- OSI Model and TCP/IP
- IP addressing and subnetting
- Network protocols (HTTP, FTP, SSH, DNS, SMB)
- Network scanning with Nmap
- Packet analysis with Wireshark
- ARP spoofing and MITM attacks
- VPNs and tunneling

**Practice Scripts:**
- ARP scanner
- Port scanner (advanced)
- Service enumeration tool
- Packet analyzer
- DNS enumeration script

**Learning Outcomes:**
- Understand network protocols at a deep level
- Perform network reconnaissance
- Analyze network traffic
- Execute man-in-the-middle attacks

[📖 Module 2 Details](./02-networking/README.md)

---

### 🔐 Module 3: Web Application Security
**Directory:** `03-web-security/`
**Status:** ✅ Lessons available

Master web application penetration testing and common vulnerabilities.

**Topics:**
- HTTP/HTTPS fundamentals
- OWASP Top 10
- SQL Injection (SQLi) ✅
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Directory traversal and file inclusion
- Authentication bypass techniques
- Session management attacks
- Burp Suite and OWASP ZAP

**Practice Scripts:**
- `web_crawler.sh` - Web enumeration tool ✅
- SQL injection scanner
- XSS payload generator
- Directory bruteforcer
- Cookie/session analyzer

**Learning Outcomes:**
- Identify and exploit SQL injection vulnerabilities
- Perform XSS attacks
- Test authentication mechanisms
- Use professional tools (Burp Suite, SQLMap)

[📖 Module 3 Details](./03-web-security/README.md)

---

### 🔑 Module 4: Cryptography
**Directory:** `04-cryptography/`

Understand cryptographic concepts and password cracking techniques.

**Topics:**
- Cryptography fundamentals
- Symmetric vs asymmetric encryption
- Hashing algorithms (MD5, SHA, bcrypt)
- Password cracking (John, Hashcat)
- SSL/TLS security
- PKI and digital certificates
- Cryptanalysis basics

**Practice Scripts:**
- Dictionary attack tool
- Password strength analyzer
- Hash identifier
- Base64 encoder/decoder
- SSL certificate validator

**Learning Outcomes:**
- Understand encryption algorithms
- Crack password hashes
- Analyze SSL/TLS implementations
- Perform basic cryptanalysis

[📖 Module 4 Details](./04-cryptography/README.md)

---

### 📡 Module 5: Wireless Security
**Directory:** `05-wireless-security/`

Learn wireless network attacks and defense techniques.

**Topics:**
- Wireless networking fundamentals
- WEP, WPA, WPA2, WPA3
- Wireless reconnaissance
- WPA/WPA2 cracking with Aircrack-ng
- Evil Twin attacks
- Rogue access points
- Bluetooth and RFID security

**Practice Scripts:**
- WiFi scanner
- WPS attack automation
- Deauthentication script
- Handshake capture tool
- Wireless network mapper

**Learning Outcomes:**
- Crack WPA/WPA2 passwords
- Set up evil twin access points
- Perform wireless reconnaissance
- Understand wireless security protocols

[📖 Module 5 Details](./05-wireless-security/README.md)

---

### 💥 Module 6: Exploitation & Vulnerability Assessment
**Directory:** `06-exploitation/`

Master exploitation techniques and vulnerability assessment.

**Topics:**
- Vulnerability scanning (Nessus, OpenVAS)
- Metasploit Framework
- Exploit development basics
- Buffer overflow attacks
- Privilege escalation (Linux & Windows)
- Exploiting common services
- CVE research and exploit databases

**Practice Scripts:**
- Vulnerability scanner
- Metasploit automation
- Reverse shell generator
- Privilege escalation checker (enhanced)
- Payload encoder

**Learning Outcomes:**
- Use Metasploit effectively
- Exploit common vulnerabilities
- Perform privilege escalation
- Understand exploit development

[📖 Module 6 Details](./06-exploitation/README.md)

---

### 🎯 Module 7: Post-Exploitation
**Directory:** `07-post-exploitation/`

Learn what to do after gaining access to a system.

**Topics:**
- Maintaining access and persistence
- Data exfiltration techniques
- Credential harvesting
- Lateral movement
- Covering tracks and anti-forensics
- Pivoting and tunneling
- Active Directory attacks

**Practice Scripts:**
- Persistence script
- Keylogger
- Credential dumper
- Log cleaner
- Data exfiltration tool

**Learning Outcomes:**
- Maintain persistent access
- Move laterally through networks
- Harvest credentials
- Cover your tracks
- Exfiltrate data covertly

[📖 Module 7 Details](./07-post-exploitation/README.md)

---

### 🎭 Module 8: Social Engineering
**Directory:** `08-social-engineering/`

Master the human element of hacking.

**Topics:**
- Social engineering fundamentals
- Phishing attacks
- Pretexting and impersonation
- Physical security testing
- OSINT (Open Source Intelligence)
- Social Engineering Toolkit (SET)

**Practice Scripts:**
- Phishing page cloner
- Email header analyzer
- OSINT data gatherer
- Credential harvester
- Information aggregator

**Learning Outcomes:**
- Create convincing phishing campaigns
- Gather OSINT effectively
- Understand psychological manipulation
- Perform physical security assessments

[📖 Module 8 Details](./08-social-engineering/README.md)

---

### 🏆 Module 9: CTF Practice
**Directory:** `09-ctf-practice/`

Apply your skills in Capture The Flag challenges.

**Challenges:**
- Linux privilege escalation
- Web application exploitation
- Cryptography puzzles
- Network forensics
- Binary exploitation
- Reverse engineering
- Steganography
- OSINT challenges

**Learning Outcomes:**
- Solve complex security challenges
- Think like an attacker
- Combine multiple techniques
- Compete in CTF competitions

[📖 Module 9 Details](./09-ctf-practice/README.md)

---

### 🎓 Module 10: Capstone Projects
**Directory:** `10-capstone-projects/`

Demonstrate mastery with real-world project simulations.

**Projects:**
1. Full network penetration test
2. Web application security assessment
3. Vulnerability assessment and reporting
4. Red team engagement simulation

**Deliverables:**
- Professional penetration testing reports
- Detailed methodology documentation
- Remediation recommendations
- Executive summaries

[📖 Module 10 Details](./10-capstone-projects/README.md)

---

## 📊 Progress Tracking

Track your progress using the comprehensive tracker:

**[📋 PROGRESS TRACKER](./PROGRESS-TRACKER.md)**

The tracker includes:
- Module completion checkboxes
- Lesson checklists
- Script completion tracking
- Skills assessment
- Study log
- Certification goals

---

## 🛠️ Tools & Software

### Essential Tools (Pre-installed on Kali Linux):

**Reconnaissance:**
- nmap, masscan, autorecon
- gobuster, dirb, ffuf
- whois, dig, dnsenum

**Web Application:**
- Burp Suite, OWASP ZAP
- sqlmap, nikto
- wfuzz, wpscan

**Exploitation:**
- Metasploit Framework
- searchsploit
- msfvenom

**Password Cracking:**
- John the Ripper
- Hashcat
- Hydra

**Wireless:**
- Aircrack-ng suite
- Wifite
- Reaver

**Post-Exploitation:**
- Mimikatz
- BloodHound
- PowerSploit

---

## 📚 Learning Resources

### Online Platforms:
- **TryHackMe** - Guided, interactive learning
- **HackTheBox** - Advanced challenges
- **PortSwigger Web Security Academy** - Free web security training
- **PentesterLab** - Hands-on exercises
- **VulnHub** - Vulnerable VMs for practice

### Books:
- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "The Hacker Playbook 3" by Peter Kim
- "Penetration Testing" by Georgia Weidman
- "Metasploit: The Penetration Tester's Guide"
- "RTFM: Red Team Field Manual"

### Certifications:
- **CEH** (Certified Ethical Hacker)
- **OSCP** (Offensive Security Certified Professional)
- **eWPT** (eLearnSecurity Web Application Penetration Tester)
- **PNPT** (Practical Network Penetration Tester)

---

## ⚖️ Legal & Ethical Guidelines

### CRITICAL RULES:

1. **Authorization is Mandatory**
   - NEVER test systems without written permission
   - Use only authorized targets (your own VMs, lab environments, bug bounty programs)

2. **Respect Scope**
   - Stay within defined boundaries
   - Don't exceed authorized access

3. **Practice Environments:**
   - Your own virtual machines
   - Deliberately vulnerable apps (DVWA, bWAPP)
   - CTF platforms (TryHackMe, HackTheBox)
   - Bug bounty programs (HackerOne, Bugcrowd)

4. **Professional Ethics:**
   - Maintain confidentiality
   - Report vulnerabilities responsibly
   - Follow coordinated disclosure

**⚠️ WARNING:** Unauthorized hacking is illegal and can result in criminal prosecution. Always ensure you have explicit permission before testing any system.

---

## 🚀 Getting Started

### Quick Start Guide:

1. **Set up your environment:**
   ```bash
   # If using Kali Linux, you're ready!
   # Otherwise, install in VM
   ```

2. **Configure vim:**
   ```bash
   # Already done if you followed setup
   cat ~/.vimrc
   ```

3. **Start with Module 1:**
   ```bash
   cd 01-linux-basics
   cat README.md
   ```

4. **Track your progress:**
   ```bash
   # Open PROGRESS-TRACKER.md
   # Mark lessons as complete
   ```

5. **Practice, practice, practice:**
   - Run the provided scripts
   - Complete all exercises
   - Experiment in safe environments

---

## 🤝 Support & Community

### Getting Help:
- Re-read lesson materials
- Check provided resources
- Join cybersecurity communities (Reddit: r/netsec, r/AskNetsec)
- Practice on guided platforms (TryHackMe)

### Contributing:
This course is designed for personal learning. If you find errors or have suggestions:
- Document issues clearly
- Test corrections thoroughly
- Maintain ethical standards

---

## 📝 Course Completion

### To Complete This Course:

1. ✅ Finish all 10 modules
2. ✅ Complete all hands-on exercises
3. ✅ Run and understand all practice scripts
4. ✅ Solve CTF challenges
5. ✅ Complete capstone project
6. ✅ Write a professional penetration test report

### Certificate of Completion:
Upon finishing all modules and the capstone project, you'll have:
- Comprehensive ethical hacking skills
- Portfolio of scripts and reports
- Readiness for professional certifications (CEH, OSCP)

---

## 🎯 Learning Path Recommendations

### Beginner Path (No Experience):
1. Module 1: Linux Basics (3-4 weeks)
2. Module 2: Networking (3-4 weeks)
3. Module 3: Web Security (4-6 weeks)
4. Module 4: Cryptography (2-3 weeks)
5. Module 9: CTF Practice (ongoing)

### Intermediate Path (Some IT Experience):
1. Quick review of Module 1
2. Module 2: Networking (2 weeks)
3. Module 3: Web Security (3 weeks)
4. Module 6: Exploitation (4 weeks)
5. Module 7: Post-Exploitation (3 weeks)
6. Module 9-10: CTF & Capstone

### Advanced Path (Experienced IT):
1. All modules in sequence
2. Focus on advanced techniques
3. Contribute to bug bounty programs
4. Prepare for OSCP certification

---

## 📞 Final Notes

**Remember:**
- Ethical hacking requires patience and persistence
- Failure is part of learning
- Always stay within legal boundaries
- Continuous learning is essential in cybersecurity

**Good luck on your ethical hacking journey!**

---

**Version:** 1.0
**Author:** Ethical Hacking Course Team
**License:** For educational purposes only
**Last Updated:** December 2025
