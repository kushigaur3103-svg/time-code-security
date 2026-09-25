import secrets
if secrets.compare_digest(request_token, stored_token):
    grant_access()
