# Insecure API Example (Python / Flask)

This example demonstrates a Python Flask API endpoint riddled with critical vulnerabilities from the OWASP API Security Top 10. **Do not use this code in production.**

```python
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# Mock database connection
def get_db():
    return sqlite3.connect('ecommerce.db')

@app.route('/api/v1/users/<int:user_id>/payment_methods', methods=['GET'])
def get_payment_methods(user_id):
    """
    VULNERABILITY 1: Broken Object Level Authorization (BOLA - API1:2023)
    The endpoint takes the user_id directly from the URL. It does NOT check 
    if the currently authenticated user actually is `user_id`. An attacker 
    can iterate through IDs to steal credit card data from other users.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    # VULNERABILITY 2: SQL Injection (API8:2023 Security Misconfiguration / traditional injection)
    # The user_id is concatenated directly into the query instead of being parameterized.
    query = f"SELECT card_number, exp_date FROM payments WHERE user_id = {user_id}"
    cursor.execute(query)
    
    records = cursor.fetchall()
    
    # VULNERABILITY 3: Broken Object Property Level Authorization (API3:2023)
    # The backend returns the raw database row, which includes the full credit 
    # card number instead of masking it (e.g., ****-****-****-1234).
    return jsonify(records)

@app.route('/api/v1/users/profile', methods=['POST'])
def update_profile():
    """
    VULNERABILITY 4: Mass Assignment (API3:2023)
    The endpoint blindly takes the entire JSON payload and applies it to the database.
    An attacker can send `{"is_admin": true}` in the JSON body, and the backend 
    will upgrade their privileges.
    """
    data = request.json
    user_id = request.headers.get('X-User-Id') # Insecure identity validation
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Blindly updating whatever fields the user provided
    for key, value in data.items():
        cursor.execute(f"UPDATE users SET {key} = '{value}' WHERE id = {user_id}")
        
    conn.commit()
    return jsonify({"status": "success"})

if __name__ == '__main__':
    # VULNERABILITY 5: Security Misconfiguration (API8:2023)
    # Running Flask with debug=True in production exposes detailed stack traces
    app.run(host='0.0.0.0', port=5000, debug=True)
```
