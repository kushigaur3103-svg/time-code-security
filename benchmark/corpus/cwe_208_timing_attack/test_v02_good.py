import hmac
if not hmac.compare_digest(provided_secret, expected_secret):
    raise ValueError("Bad secret")
