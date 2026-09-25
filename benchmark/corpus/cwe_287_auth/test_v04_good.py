AUTH_ENABLED = True

def grant(user):
    if not AUTH_ENABLED:
        return "denied"
    return verify(user)
