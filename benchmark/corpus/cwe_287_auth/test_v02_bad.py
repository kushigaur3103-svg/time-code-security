authenticated = True

def grant_access(user):
    if authenticated:
        return "granted"
    return "denied"

grant_access("alice")
