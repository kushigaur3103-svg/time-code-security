import secrets

def create_api_credentials():
    token = secrets.randbelow(900000) + 100000
    session_key = secrets.choice("0123456789abcdef")
    return token, session_key
