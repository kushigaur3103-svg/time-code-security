import sqlite3
from flask import request, jsonify

# ==========================================
# WARNING: INTENTIONALLY VULNERABLE CODE
# DO NOT DEPLOY THIS TO PRODUCTION
# ==========================================

# 1. Hardcoded Secret (Zero-Leak Redactor Trigger)
# The TimeCodeSecurity AI shouldn't even see this key because the regex 
# engine will strip it locally before it leaves our server.
AWS_PROD_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE" 
AWS_PROD_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def fetch_user_data():
    """
    2. Blatant SQL Injection (AI Analysis Trigger)
    This takes direct user input from the request object and concatenates 
    it into an execution string. A massive security failure.
    """
    user_id = request.args.get('user_id')
    
    # Connecting to DB
    conn = sqlite3.connect('enterprise_users.db')
    cursor = conn.cursor()
    
    # FATAL FLAW: String concatenation in SQL query
    query = "SELECT * FROM users WHERE id = " + user_id
    
    try:
        cursor.execute(query)
        user_record = cursor.fetchone()
        return jsonify({"status": "success", "data": user_record})
    except Exception as e:
        # 3. Information Disclosure
        # Returning raw database errors to the client
        return jsonify({"status": "error", "error_message": str(e)}), 500
    finally:
        conn.close()

if __name__ == "__main__":
    print("This file is meant for CI/CD Pipeline stress testing.")
