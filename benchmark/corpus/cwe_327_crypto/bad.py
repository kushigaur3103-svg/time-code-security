from flask import request
import hashlib

def register_user():
    password = request.form.get("password")
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    return pwd_hash
