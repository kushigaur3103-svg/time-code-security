import secrets

def issue_session_key():
    session_key = secrets.token_hex(32)
    return session_key

print(issue_session_key())
