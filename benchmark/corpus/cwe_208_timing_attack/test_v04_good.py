import hmac
if hmac.compare_digest(computed_signature, request_signature):
    process()
