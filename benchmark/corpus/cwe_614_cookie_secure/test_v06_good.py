token = "abc123"
opts = {"secure": True, "httponly": True}
response.set_cookie("sid", token, **opts)
