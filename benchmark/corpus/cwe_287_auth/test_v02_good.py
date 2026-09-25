import bcrypt

def login(username, password):
    stored = fetch_hash(username)
    if bcrypt.checkpw(password.encode(), stored):
        session["user_id"] = username
        return True
    return False
