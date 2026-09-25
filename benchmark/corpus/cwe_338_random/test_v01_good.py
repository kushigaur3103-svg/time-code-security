import secrets

def generate_auth_token():
    auth_token = secrets.token_hex(32)
    return auth_token

print(generate_auth_token())
