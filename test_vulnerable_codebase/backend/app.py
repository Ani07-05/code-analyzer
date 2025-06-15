#!/usr/bin/env python3
"""
VulnShop - Intentionally Vulnerable E-commerce Application
Created for security testing and demonstration purposes
Contains multiple critical vulnerabilities across different categories
"""

from flask import Flask, request, render_template_string, redirect, session, jsonify, send_file
import sqlite3
import subprocess
import hashlib
import os
import pickle
import jwt
import requests
from datetime import datetime, timedelta
import logging

# Configure logging (VULNERABILITY: Debug logging in production)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded Secret Keys
app.secret_key = "super_secret_key_12345"  # Never do this in production!
JWT_SECRET = "jwt_secret_key_dont_change"  # Hardcoded JWT secret
API_KEY = "api_key_admin_2023"  # Hardcoded API key

# VULNERABILITY 2: Insecure Database Configuration
DATABASE = 'vulnshop.db'
DB_PASSWORD = "admin123"  # Hardcoded database password

@app.route('/')
def home():
    """Home page with user session info"""
    username = session.get('username', 'Guest')
    # VULNERABILITY 3: Information Disclosure
    debug_info = f"Session ID: {session.get('session_id', 'None')}, Server: {request.environ.get('SERVER_NAME')}"
    
    return render_template_string('''
    <html>
    <head><title>VulnShop - Vulnerable E-commerce</title></head>
    <body>
        <h1>Welcome to VulnShop, {{ username }}!</h1>
        <p>{{ debug_info }}</p>
        <a href="/login">Login</a> | <a href="/products">Products</a> | <a href="/admin">Admin</a>
    </body>
    </html>
    ''', username=username, debug_info=debug_info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login endpoint with multiple vulnerabilities"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABILITY 4: SQL Injection - Direct string interpolation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        logger.debug(f"Executing query: {query}")  # VULNERABILITY: Logging sensitive data
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                # VULNERABILITY 5: Weak Session Management
                session['username'] = username
                session['user_id'] = user[0]
                session['session_id'] = hashlib.md5(username.encode()).hexdigest()  # Predictable session ID
                
                # VULNERABILITY 6: Information Disclosure in Success Response
                return f"Login successful! Welcome {username}. Your user ID is {user[0]}"
            else:
                # VULNERABILITY 7: Username Enumeration
                return "Invalid username or password. User may not exist."
                
        except Exception as e:
            # VULNERABILITY 8: Error Information Disclosure
            return f"Database error: {str(e)}"
    
    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/products')
def products():
    """Product search with XSS vulnerability"""
    search_query = request.args.get('search', '')
    category = request.args.get('category', 'all')
    
    # VULNERABILITY 9: SQL Injection in search
    query = f"SELECT * FROM products WHERE name LIKE '%{search_query}%' AND category='{category}'"
    
    try:
        conn = sqlite3.connect(DATABASE)
        products = conn.execute(query).fetchall()
        conn.close()
        
        # VULNERABILITY 10: Cross-Site Scripting (XSS) - Reflected
        return f'''
        <html>
        <body>
            <h1>Product Search Results</h1>
            <p>Search query: {search_query}</p>
            <p>Category: {category}</p>
            <div>Products found: {len(products)}</div>
        </body>
        </html>
        '''
    except Exception as e:
        return f"Search error: {str(e)}"

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Product details with IDOR vulnerability"""
    # VULNERABILITY 11: Insecure Direct Object Reference (IDOR)
    # No authorization check - any user can access any product
    
    query = f"SELECT * FROM products WHERE id = {product_id}"  # VULNERABILITY: SQL Injection (numeric)
    
    try:
        conn = sqlite3.connect(DATABASE)
        product = conn.execute(query).fetchone()
        conn.close()
        
        if product:
            return f"Product: {product[1]}, Price: ${product[2]}, Internal Cost: ${product[3]}"  # VULNERABILITY: Sensitive data exposure
        return "Product not found"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/admin/users')
def admin_users():
    """Admin panel with insufficient access control"""
    # VULNERABILITY 12: Missing Authentication/Authorization
    # No check if user is actually an admin
    
    user_id = request.args.get('id', '')
    
    if user_id:
        # VULNERABILITY 13: SQL Injection in admin panel  
        query = f"SELECT username, email, credit_card FROM users WHERE id = '{user_id}'"
        
        try:
            conn = sqlite3.connect(DATABASE)
            user_data = conn.execute(query).fetchone()
            conn.close()
            
            if user_data:
                # VULNERABILITY 14: Sensitive Data Exposure
                return f"User: {user_data[0]}, Email: {user_data[1]}, CC: {user_data[2]}"
            return "User not found"
        except Exception as e:
            return f"Database error: {str(e)}"
    
    # VULNERABILITY 15: Information Disclosure - List all users
    try:
        conn = sqlite3.connect(DATABASE)
        users = conn.execute("SELECT id, username, email FROM users").fetchall()
        conn.close()
        
        user_list = "<br>".join([f"ID: {u[0]}, User: {u[1]}, Email: {u[2]}" for u in users])
        return f"<h1>All Users</h1>{user_list}"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/admin/backup')
def admin_backup():
    """System backup with command injection"""
    backup_path = request.args.get('path', '/tmp')
    backup_name = request.args.get('name', 'backup')
    
    # VULNERABILITY 16: Command Injection
    command = f"tar -czf /tmp/{backup_name}.tar.gz {backup_path}"
    
    try:
        # VULNERABILITY 17: Unsafe subprocess execution
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        
        return f'''
        <h1>Backup Results</h1>
        <p>Command executed: {command}</p>
        <pre>STDOUT: {result.stdout}</pre>
        <pre>STDERR: {result.stderr}</pre>
        <p>Return code: {result.returncode}</p>
        '''
    except Exception as e:
        return f"Backup failed: {str(e)}"

@app.route('/download')
def download_file():
    """File download with path traversal vulnerability"""
    filename = request.args.get('file', '')
    
    # VULNERABILITY 18: Path Traversal
    file_path = f"/var/www/uploads/{filename}"
    
    try:
        # VULNERABILITY 19: Unrestricted file access
        with open(file_path, 'r') as f:
            content = f.read()
        
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"File error: {str(e)}"

@app.route('/api/process_payment', methods=['POST'])
def process_payment():
    """Payment processing with multiple vulnerabilities"""
    # VULNERABILITY 20: Missing CSRF Protection
    # VULNERABILITY 21: No input validation
    
    card_number = request.form.get('card_number', '')
    cvv = request.form.get('cvv', '')
    amount = request.form.get('amount', '0')
    
    # VULNERABILITY 22: Weak cryptographic hash (MD5)
    card_hash = hashlib.md5(card_number.encode()).hexdigest()
    
    # VULNERABILITY 23: Logging sensitive data
    logger.info(f"Processing payment: Card={card_number}, CVV={cvv}, Amount=${amount}")
    
    # VULNERABILITY 24: SQL Injection in payment logging
    payment_query = f"INSERT INTO payments (card_hash, amount, timestamp) VALUES ('{card_hash}', {amount}, '{datetime.now()}')"
    
    try:
        conn = sqlite3.connect(DATABASE)
        conn.execute(payment_query)
        conn.commit()
        conn.close()
        
        # VULNERABILITY 25: Information Disclosure in API response
        return jsonify({
            "status": "success",
            "card_hash": card_hash,
            "amount": amount,
            "internal_fee": float(amount) * 0.03,  # Internal business logic exposed
            "database_query": payment_query  # Database query exposed!
        })
    except Exception as e:
        return jsonify({"error": str(e), "query": payment_query})

@app.route('/upload', methods=['POST'])
def upload_file():
    """File upload with multiple vulnerabilities"""
    if 'file' not in request.files:
        return "No file uploaded"
    
    file = request.files['file']
    filename = file.filename
    
    # VULNERABILITY 26: Unrestricted file upload - no validation
    # VULNERABILITY 27: Path traversal in filename
    upload_path = f"/var/www/uploads/{filename}"
    
    try:
        file.save(upload_path)
        
        # VULNERABILITY 28: Unsafe deserialization
        if filename.endswith('.pkl'):
            with open(upload_path, 'rb') as f:
                data = pickle.load(f)  # Dangerous!
                return f"Pickle loaded: {data}"
        
        return f"File uploaded successfully: {upload_path}"
    except Exception as e:
        return f"Upload error: {str(e)}"

@app.route('/api/user_data/<user_id>')
def get_user_api(user_id):
    """API endpoint with multiple vulnerabilities"""
    api_key = request.headers.get('X-API-Key', '')
    
    # VULNERABILITY 29: Weak API authentication
    if api_key != API_KEY:  # Hardcoded API key comparison
        return jsonify({"error": "Invalid API key"}), 401
    
    # VULNERABILITY 30: NoSQL-style injection (if using NoSQL)
    # VULNERABILITY 31: SQL Injection in API
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    try:
        conn = sqlite3.connect(DATABASE)
        user = conn.execute(query).fetchone()
        conn.close()
        
        if user:
            # VULNERABILITY 32: Excessive data exposure in API
            return jsonify({
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "password_hash": user[3],  # Never expose password hashes!
                "credit_card": user[4],    # Never expose credit cards!
                "ssn": user[5],           # Never expose SSNs!
                "internal_notes": user[6], # Internal data exposed
                "creation_ip": user[7],    # PII exposed
                "last_login": user[8]
            })
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 500

if __name__ == '__main__':
    # VULNERABILITY 33: Debug mode in production
    # VULNERABILITY 34: Binding to all interfaces (0.0.0.0)
    # VULNERABILITY 35: No HTTPS enforcement
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)