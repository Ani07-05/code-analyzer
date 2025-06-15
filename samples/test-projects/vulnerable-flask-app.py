from flask import Flask, request, render_template_string
import sqlite3
import hashlib

app = Flask(__name__)

# Vulnerable: Hardcoded secret key
app.secret_key = "hardcoded_secret_123"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Vulnerable: SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect('users.db')
    result = conn.execute(query).fetchone()
    
    # Vulnerable: Weak password hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    return f"Welcome {username}!"

@app.route('/search')
def search():
    query = request.args.get('q')
    # Vulnerable: XSS
    template = f"<h1>Search results for: {query}</h1>"
    return render_template_string(template)

if __name__ == '__main__':
    # Vulnerable: Debug mode in production
    app.run(debug=True, host='0.0.0.0')
