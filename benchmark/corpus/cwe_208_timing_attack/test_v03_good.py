import secrets
if secrets.compare_digest(api_key.encode(), VALID_API_KEY.encode()):
    return True
