import secrets
if secrets.compare_digest(received_hmac, expected_hmac):
    verify_webhook()
