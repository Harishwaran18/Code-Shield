#!/usr/bin/env python3
"""
SecureHack AI - Vulnerability Scanner Test Script
This script tests the AI vulnerability scanner with various security issues.
"""

import requests
import json
import time
import sys
from datetime import datetime

# ==================== TEST CONFIGURATION ====================
SERVER_URL = "http://localhost:8000"
TIMEOUT = 30  # seconds

# ==================== TEST CASE 1: COMPREHENSIVE VULNERABLE CODE ====================
VULNERABLE_CODE_1 = '''#!/usr/bin/env python3
"""
Vulnerable Web Application - DO NOT USE IN PRODUCTION
This file contains intentional security vulnerabilities for testing.
"""

import os
import sys
import subprocess
import pickle
import sqlite3
import hashlib
import hmac
import base64
import json
import requests
import flask
from flask import Flask, request, render_template, redirect, session
import django
from django.db import connection
import paramiko
import cryptography
from cryptography.fernet import Fernet
import bcrypt
import jwt

# ==================== HARDCODED SECRETS ====================
# Critical vulnerabilities - Hardcoded credentials

DATABASE_PASSWORD = "admin123"
ROOT_PASSWORD = "toor2024"
API_SECRET = "sk_live_EXAMPLE_PLACEHOLDER_NOT_A_REAL_KEY"
AWS_ACCESS_KEY = "AKIA_EXAMPLE_PLACEHOLDER"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENCRYPTION_KEY = "my-super-secret-key-12345"
JWT_SECRET = "jwt_secret_key_2024"
FERNET_KEY = "k8rZ_7gXq2tRwY3sN6mP9jL1vC4xZ8aB="
GITHUB_TOKEN = "ghp_EXAMPLE_PLACEHOLDER_NOT_A_REAL_TOKEN"
STRIPE_KEY = "sk_test_EXAMPLE_PLACEHOLDER_NOT_A_REAL_KEY"

# ==================== COMMAND INJECTION ====================
# High severity - Command injection vulnerabilities

def ping_host(user_input):
    # BAD: Direct command concatenation
    os.system("ping -c 4 " + user_input)
    
    # BAD: Using os.popen
    result = os.popen("ping " + user_input).read()
    
    # BAD: Subprocess with shell=True
    subprocess.run("ping " + user_input, shell=True)
    
    # BAD: Using os.system with format
    os.system(f"nslookup {user_input}")
    
    return result

def execute_command(cmd):
    # BAD: Multiple command execution methods
    subprocess.call(cmd, shell=True)
    subprocess.Popen(cmd, shell=True)
    os.execl("/bin/sh", "sh", "-c", cmd)
    os.system("bash -c '" + cmd + "'")
    
    # BAD: Using eval with user input
    eval(f"subprocess.run('{cmd}', shell=True)")
    
    # BAD: Using exec
    exec(f"os.system('{cmd}')")

# ==================== SQL INJECTION ====================
# High severity - SQL injection vulnerabilities

def get_user_by_id(user_id):
    # BAD: Direct string concatenation
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable query 1
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    # Vulnerable query 2
    username = request.args.get('username')
    query2 = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query2)
    
    # Vulnerable query 3
    password = request.form.get('password')
    query3 = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    cursor.execute(query3)
    
    # Vulnerable query 4 - Django raw query
    from django.db import connection
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM auth_user WHERE username = '" + username + "'")
    
    # Vulnerable query 5 - SQLAlchemy text
    from sqlalchemy import text
    session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
    
    return cursor.fetchall()

# ==================== INSECURE DESERIALIZATION ====================
# Critical severity - Pickle/YAML deserialization

def load_user_data(data):
    # BAD: Unsafe pickle deserialization
    user_object = pickle.loads(data)
    
    # BAD: Loading pickle from file
    with open('user.pkl', 'rb') as f:
        user_data = pickle.load(f)
    
    # BAD: Yaml deserialization
    import yaml
    yaml.load(data, Loader=yaml.Loader)  # Unsafe loader
    
    # BAD: JSON with eval
    json_data = json.loads(data)
    eval(json_data.get('callback', ''))

# ==================== PATH TRAVERSAL ====================
# Medium severity - File path manipulation

def read_file(filename):
    # BAD: Path traversal vulnerability
    base_path = "/var/www/files/"
    full_path = base_path + filename
    
    with open(full_path, 'r') as f:
        return f.read()
    
    # BAD: Another path traversal
    import os
    user_file = request.args.get('file')
    os.remove(f"/tmp/{user_file}")

# ==================== INSECURE FILE PERMISSIONS ====================
# Medium severity - World-writable files

def setup_files():
    # BAD: Creating world-writable files
    with open('/etc/config.json', 'w') as f:
        f.write('{"admin": true}')
    os.chmod('/etc/config.json', 0o777)  # rwx for everyone
    
    # BAD: Setting SUID bit
    os.chmod('/usr/bin/myapp', 0o4755)
    
    # BAD: World-writable directory
    os.mkdir('/tmp/data', 0o777)

# ==================== WEAK CRYPTOGRAPHY ====================
# Medium severity - Weak encryption

def weak_encryption():
    # BAD: MD5 hash (collision vulnerable)
    password = "user123"
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    
    # BAD: SHA1 (deprecated)
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    
    # BAD: Weak key generation
    key = b'12345678'  # Too short
    iv = b'12345678'   # Predictable IV
    
    # BAD: ECB mode (leaks patterns)
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    
    # BAD: Hardcoded salt
    salt = b'fixed_salt'
    hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(4))  # Weak rounds

# ==================== SSL/TLS MISCONFIGURATION ====================
# Medium severity - Disabled SSL verification

def make_request():
    # BAD: Disabled SSL verification
    response = requests.get('https://api.example.com', verify=False)
    
    # BAD: Using HTTP instead of HTTPS
    response2 = requests.get('http://api.example.com')
    
    # BAD: Ignoring SSL errors
    import ssl
    context = ssl._create_unverified_context()
    
    # BAD: Weak SSL protocol
    import socket
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)  # Deprecated

# ==================== INFORMATION DISCLOSURE ====================
# Medium severity - Stack traces to users

def error_handling():
    try:
        result = 1/0
    except Exception as e:
        # BAD: Showing full error to user
        return f"Error: {str(e)} - {repr(e)} - {sys.exc_info()}"
    
    # BAD: Debug mode in production
    app = Flask(__name__)
    app.debug = True
    
    # BAD: Printing sensitive data
    print(f"Database password: {DATABASE_PASSWORD}")

# ==================== INSECURE RANDOMNESS ====================
# Medium severity - Predictable random numbers

def generate_token():
    # BAD: Using random for security
    import random
    token = random.randint(100000, 999999)
    
    # BAD: Using time as seed
    import time
    random.seed(time.time())
    
    # BAD: Weak token generation
    import string
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# ==================== CORS MISCONFIGURATION ====================
# Medium severity - Overly permissive CORS

def cors_config():
    app = Flask(__name__)
    
    # BAD: Allow all origins
    @app.after_request
    def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', '*')
        response.headers.add('Access-Control-Allow-Methods', '*')
        return response

# ==================== JWT VULNERABILITIES ====================
# High severity - JWT algorithm confusion

def jwt_vulnerabilities():
    # BAD: Using 'none' algorithm
    token = jwt.encode({'user': 'admin'}, key=None, algorithm='none')
    
    # BAD: Hardcoded secret
    decoded = jwt.decode(token, 'secret', algorithms=['HS256'])
    
    # BAD: Algorithm confusion (accepting HS256 with RSA public key)
    decoded2 = jwt.decode(token, verify=False)

# ==================== XXE VULNERABILITY ====================
# High severity - XML External Entity

def parse_xml(xml_data):
    # BAD: XXE vulnerable parser
    import xml.etree.ElementTree as ET
    parser = ET.XMLParser()
    tree = ET.fromstring(xml_data, parser=parser)
    
    # BAD: lxml with external entities
    from lxml import etree
    tree2 = etree.parse(xml_data)

# ==================== SERVER-SIDE REQUEST FORGERY ====================
# Medium severity - SSRF

def fetch_url():
    # BAD: SSRF vulnerability
    url = request.args.get('url')
    response = requests.get(url)
    
    # BAD: Accessing internal services
    internal_url = f"http://localhost:8080/api/{url}"
    requests.get(internal_url)

# ==================== MAIN FUNCTION ====================
if __name__ == "__main__":
    app = Flask(__name__)
    app.run(host='0.0.0.0', port=5000, debug=True)
'''

# ==================== TEST CASE 2: CLEAN CODE (NO VULNERABILITIES) ====================
CLEAN_CODE = '''#!/usr/bin/env python3
"""
Secure Web Application - Example of secure coding practices
"""

import os
import subprocess
import sqlite3
import hashlib
import secrets
import bcrypt
from flask import Flask, request, session
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ==================== SECURE CONFIGURATION ====================
# Using environment variables for secrets
DATABASE_PASSWORD = os.environ.get('DB_PASSWORD')
API_KEY = os.environ.get('API_KEY')

# ==================== SECURE COMMAND EXECUTION ====================
def ping_host(hostname):
    # GOOD: Using subprocess with argument list
    result = subprocess.run(
        ['ping', '-c', '4', hostname],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout

# ==================== SECURE SQL QUERIES ====================
def get_user(username):
    # GOOD: Using parameterized queries
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )
    return cursor.fetchone()

# ==================== SECURE FILE OPERATIONS ====================
def read_file(filename):
    # GOOD: Path validation
    import os.path
    base_path = "/var/www/files/"
    
    # Validate path
    full_path = os.path.abspath(os.path.join(base_path, filename))
    if not full_path.startswith(base_path):
        raise ValueError("Invalid file path")
    
    with open(full_path, 'r') as f:
        return f.read()

# ==================== SECURE CRYPTOGRAPHY ====================
def hash_password(password):
    # GOOD: Using bcrypt with proper salt
    salt = bcrypt.gensalt(12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def generate_token():
    # GOOD: Using secrets module for cryptography
    return secrets.token_urlsafe(32)

# ==================== SECURE REQUESTS ====================
def fetch_data():
    # GOOD: SSL verification enabled
    response = requests.get(
        'https://api.example.com/data',
        verify=True,
        timeout=10
    )
    return response.json()

# ==================== RATE LIMITING ====================
from functools import wraps
from datetime import datetime, timedelta

rate_limit_storage = {}

def rate_limit(limit=5, per=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get client IP
            ip = request.remote_addr
            
            # Clean old entries
            now = datetime.now()
            if ip in rate_limit_storage:
                rate_limit_storage[ip] = [
                    t for t in rate_limit_storage[ip] 
                    if now - t < timedelta(seconds=per)
                ]
            else:
                rate_limit_storage[ip] = []
            
            # Check rate limit
            if len(rate_limit_storage[ip]) >= limit:
                return "Rate limit exceeded", 429
            
            # Add current request
            rate_limit_storage[ip].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/login', methods=['POST'])
@rate_limit(limit=5, per=60)
def login():
    # GOOD: Rate limited login
    username = request.form['username']
    password = request.form['password']
    
    # Verify credentials securely
    user = get_user(username)
    if user and bcrypt.checkpw(password.encode(), user[2]):
        session['user'] = username
        return {"status": "success"}
    
    return {"status": "error"}, 401

# ==================== SECURE HEADERS ====================
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == "__main__":
    # GOOD: Not running in debug mode
    app.run(host='127.0.0.1', port=5000, debug=False)
'''

# ==================== TEST FUNCTION ====================
def test_vulnerability_scanner():
    """Test the vulnerability scanner with different code samples"""
    
    print("=" * 70)
    print("🔍 SECUREHACK AI - VULNERABILITY SCANNER TEST")
    print("=" * 70)
    print(f"📅 Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 Server URL: {SERVER_URL}")
    print("=" * 70)
    
    # Check if server is running
    try:
        health_response = requests.get(f"{SERVER_URL}/health", timeout=5)
        print(f"✅ Server health check: {health_response.status_code}")
        if health_response.status_code == 200:
            status = health_response.json().get('status', 'unknown')
            print(f"   Server Status: {status}")
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Cannot connect to server!")
        print("\nPlease make sure the server is running:")
        print("1. Open a new terminal")
        print("2. Run: python app.py")
        print("3. Wait for 'Uvicorn running on http://127.0.0.1:8000'")
        print("4. Run this test again")
        return
    except Exception as e:
        print(f"❌ Error checking server: {e}")
        return
    
    print("\n" + "=" * 70)
    print("🧪 TEST CASE 1: Vulnerable Code (Should find many issues)")
    print("=" * 70)
    
    try:
        start_time = time.time()
        response = requests.post(
            f"{SERVER_URL}/scan",
            json={"code": VULNERABLE_CODE_1},
            timeout=TIMEOUT
        )
        elapsed = time.time() - start_time
        
        print(f"⏱️  Scan completed in {elapsed:.2f} seconds")
        print(f"📥 Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            # Print summary
            print("\n📊 SCAN SUMMARY:")
            print("-" * 50)
            print(f"📌 Result: {data.get('result', 'N/A')}")
            print(f"⚠️  Severity: {data.get('severity', 'N/A').upper()}")
            
            vulnerabilities = data.get('vulnerabilities', [])
            print(f"🔴 Total Vulnerabilities: {len(vulnerabilities)}")
            
            if vulnerabilities:
                # Count by severity
                severity_count = {}
                for v in vulnerabilities:
                    sev = v.get('severity', 'unknown')
                    severity_count[sev] = severity_count.get(sev, 0) + 1
                
                print("\n📈 Breakdown by Severity:")
                for sev in ['critical', 'high', 'medium', 'low']:
                    count = severity_count.get(sev, 0)
                    icon = {
                        'critical': '🔥',
                        'high': '⚠️',
                        'medium': '⚡',
                        'low': 'ℹ️'
                    }.get(sev, '•')
                    print(f"   {icon} {sev.upper()}: {count}")
                
                # Show first 5 vulnerabilities as samples
                print("\n📋 Sample Vulnerabilities (first 5):")
                print("-" * 50)
                for i, v in enumerate(vulnerabilities[:5], 1):
                    print(f"\n{i}. {v.get('title', 'Unknown')}")
                    print(f"   Line: {v.get('line', 'N/A')} | Severity: {v.get('severity', 'N/A').upper()}")
                    desc = v.get('description', 'N/A')
                    print(f"   Description: {desc[:100]}..." if len(desc) > 100 else f"   Description: {desc}")
            else:
                print("❓ No vulnerabilities detected - scanner might not be working")
        else:
            print(f"❌ Error: {response.text}")
            
    except requests.exceptions.Timeout:
        print(f"❌ Scan timed out after {TIMEOUT} seconds")
    except Exception as e:
        print(f"❌ Error during scan: {e}")
    
    print("\n" + "=" * 70)
    print("🧪 TEST CASE 2: Clean Code (Should find no issues)")
    print("=" * 70)
    
    try:
        response = requests.post(
            f"{SERVER_URL}/scan",
            json={"code": CLEAN_CODE},
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            if len(vulnerabilities) == 0:
                print("✅ PASSED: No vulnerabilities found in clean code")
            else:
                print(f"❌ FAILED: Found {len(vulnerabilities)} issues in clean code")
                for v in vulnerabilities[:3]:
                    print(f"   - {v.get('title')} (Line {v.get('line')})")
        else:
            print(f"❌ Error: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("\n" + "=" * 70)
    print("📊 TEST COMPLETE")
    print("=" * 70)
    
    # Recommendations
    print("\n🔧 RECOMMENDATIONS:")
    if 'vulnerabilities' in locals() and len(vulnerabilities) > 0:
        print("✅ Scanner is detecting issues - working correctly")
    else:
        print("⚠️ Scanner didn't detect issues. Possible problems:")
        print("   1. Bandit not installed (pip install bandit)")
        print("   2. Scan endpoint not implemented correctly")
        print("   3. Server configuration issue")
    
    print("\n📝 Next Steps:")
    print("   1. If scanner worked, proceed with demo")
    print("   2. If not, check server logs for errors")
    print("   3. Verify Bandit installation: bandit --version")
    print("=" * 70)

# ==================== SIMPLE SCAN FUNCTION ====================
def simple_scan(code_sample):
    """Simple direct scan without server (for testing)"""
    print("\n🔬 Running local pattern-based scan...")
    
    patterns = {
        'password.*=': ('Hardcoded Password', 'medium'),
        'os.system': ('Command Injection', 'high'),
        'eval\\(': ('Arbitrary Code Execution', 'critical'),
        'subprocess.*shell=True': ('Shell Injection', 'high'),
        'pickle.load': ('Insecure Deserialization', 'high'),
        'sqlite3.*execute.*\\+': ('SQL Injection', 'high'),
        'chmod.*0o777': ('Insecure File Permissions', 'medium'),
        'requests.*verify=False': ('SSL Disabled', 'medium'),
        'md5\\(': ('Weak Hash', 'low'),
        'random\\(': ('Insecure Randomness', 'low')
    }
    
    findings = []
    lines = code_sample.split('\n')
    
    for i, line in enumerate(lines, 1):
        for pattern, (title, severity) in patterns.items():
            if pattern in line:
                findings.append({
                    'line': i,
                    'title': title,
                    'severity': severity,
                    'code': line.strip()
                })
    
    if findings:
        print(f"Found {len(findings)} potential issues:")
        for f in findings[:5]:
            print(f"  Line {f['line']}: {f['title']} ({f['severity']})")
    else:
        print("No issues found")
    
    return findings

# ==================== MAIN ====================
if __name__ == "__main__":
    # Parse command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--local":
            print("Running local pattern-based scan...")
            simple_scan(VULNERABLE_CODE_1)
        elif sys.argv[1] == "--clean":
            print("Testing clean code...")
            simple_scan(CLEAN_CODE)
        else:
            print("Usage: python test_scan.py [--local | --clean]")
    else:
        # Run full server test
        test_vulnerability_scanner()
    
    print("\n" + "=" * 70)