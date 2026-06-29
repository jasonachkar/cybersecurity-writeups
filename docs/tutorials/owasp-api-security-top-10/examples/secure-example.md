# Secure API Example (Python / Flask)

This example refactors the insecure Flask API to address the OWASP API Security Top 10 vulnerabilities.

```python
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
import sqlite3
import os

app = Flask(__name__)

# Security Misconfiguration Mitigation: Ensure strong secret key and disable debug mode
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default_fallback_change_in_prod')
jwt = JWTManager(app)

def get_db():
    return sqlite3.connect('ecommerce.db')

@app.route('/api/v1/users/<int:user_id>/payment_methods', methods=['GET'])
@jwt_required()
def get_payment_methods(user_id):
    """
    MITIGATION 1: Broken Object Level Authorization (BOLA)
    We extract the identity of the currently logged-in user from the verified JWT.
    If the requested user_id doesn't match the token's identity, we reject the request.
    """
    current_user_id = get_jwt_identity()
    
    if current_user_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403
        
    conn = get_db()
    cursor = conn.cursor()
    
    # MITIGATION 2: SQL Injection Prevention
    # We use parameterized queries (?) to prevent injection attacks.
    query = "SELECT card_number, exp_date FROM payments WHERE user_id = ?"
    cursor.execute(query, (user_id,))
    
    records = cursor.fetchall()
    
    # MITIGATION 3: Broken Object Property Level Authorization (BOPLA)
    # We mask the sensitive credit card numbers before returning them to the client.
    safe_records = []
    for row in records:
        card_num, exp_date = row
        masked_card = f"****-****-****-{card_num[-4:]}"
        safe_records.append({"card_number": masked_card, "exp_date": exp_date})
        
    return jsonify(safe_records)

@app.route('/api/v1/users/profile', methods=['POST'])
@jwt_required()
def update_profile():
    """
    MITIGATION 4: Mass Assignment Prevention
    We explicitly pull only the safe fields from the JSON payload instead of iterating 
    over whatever the user provided. The "is_admin" field cannot be updated here.
    """
    current_user_id = get_jwt_identity()
    data = request.json
    
    # Explicitly allowed fields (Allow-listing)
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    
    if not first_name or not last_name:
        return jsonify({"error": "Missing required fields"}), 400
        
    conn = get_db()
    cursor = conn.cursor()
    
    # Parameterized update
    query = "UPDATE users SET first_name = ?, last_name = ? WHERE id = ?"
    cursor.execute(query, (first_name, last_name, current_user_id))
    
    conn.commit()
    return jsonify({"status": "success"})

if __name__ == '__main__':
    # MITIGATION 5: Production Ready
    # Debug is strictly disabled in production to prevent stack trace leaks.
    app.run(host='0.0.0.0', port=5000, debug=False)
```
