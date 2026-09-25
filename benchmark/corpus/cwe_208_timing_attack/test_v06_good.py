import secrets
if secrets.compare_digest(auth_token, SESSION_TOKEN):
    allow()
