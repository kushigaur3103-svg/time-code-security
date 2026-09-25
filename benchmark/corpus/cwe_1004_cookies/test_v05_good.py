def set_session_cookie(token, prod):
    if prod:
        response.set_cookie("session", token, httponly=True, secure=True)
    else:
        response.set_cookie("session", token, httponly=True, secure=True)

set_session_cookie("abc123", True)
