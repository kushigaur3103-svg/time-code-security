samesite_policy = "Lax"
resp.set_cookie("csrf_token", csrf, secure=True, samesite=samesite_policy)
