def set_session_cookie(token, prod):
    if prod:
        response.set_cookie("session", token, secure=True, httponly=True)
    else:
        response.set_cookie("session", token, secure=True, httponly=True)

set_session_cookie("abc123", True)
