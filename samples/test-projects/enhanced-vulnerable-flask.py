"""Enhanced Vulnerable Flask Application for Testing"""

from flask import Flask, request, render_template_string, session
import sqlite3
import subprocess
import hashlib

app = Flask(__name__)
app.secret_key = "hardcoded_secret_123"  # HIGH RISK

# HIGH RISK: Admin route with SQL injection
@app.route('/admin/users')
def admin_users():
    user_id = request.args.get('id', '')
    query = f"SELECT * FROM users WHERE id = '{user_id}'"  # SQL Injection
    conn = sqlite3.connect('users.db')
    users = conn.execute(query).fetchall()
    return f"<h1>Users: {users}</h1>"

# HIGH RISK: Payment processing without auth
@app.route('/process_payment', methods=['POST'])
def process_payment():
    card_number = request.form.get('card_number')
    amount = request.form.get('amount')
    return f"Processing ${amount} for card {card_number[-4:]}"

# HIGH RISK: Command injection
@app.route('/admin/backup')
def admin_backup():
    path = request.args.get('path', '/tmp')
    command = f"tar -czf backup.tar.gz {path}"  # Command Injection
    result = subprocess.run(command, shell=True, capture_output=True)
    return f"Backup: {result.stdout}"

# MODERATE RISK: Login with SQL injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    query = f"SELECT * FROM users WHERE username='{username}'"  # SQL Injection
    # Weak password hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    return "Login processed"

# MODERATE RISK: XSS vulnerability
@app.route('/profile')
def user_profile():
    comment = request.args.get('comment', '')
    template = f"<h1>Profile</h1><p>{comment}</p>"  # XSS
    return render_template_string(template)

# LOW RISK: Public stats
@app.route('/api/stats')
def public_stats():
    return {"users": 100, "uptime": "99%"}

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # DEBUG in production
