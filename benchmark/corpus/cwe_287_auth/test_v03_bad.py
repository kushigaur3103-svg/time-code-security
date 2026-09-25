AUTH_ENABLED = False

def grant(user):
    if not AUTH_ENABLED:
        return "granted (auth bypassed)"
    return verify(user)
