import secrets

def issue_token(for_admin):
    if for_admin:
        auth_token = secrets.token_hex(32)
    else:
        auth_token = secrets.token_hex(16)
    return auth_token

print(issue_token(False))
