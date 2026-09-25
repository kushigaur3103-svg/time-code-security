token = "abc123"
response.set_cookie("sid", token, httponly=True, secure=True, samesite="Strict")
