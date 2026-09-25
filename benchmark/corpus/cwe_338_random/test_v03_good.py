import secrets

def make_credentials():
    creds = {"auth_secret": secrets.token_hex(32), "csrf_token": secrets.token_hex(16)}
    return creds

print(make_credentials())
