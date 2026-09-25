def issue_cookie(resp, token):
    resp.set_cookie("sid", token, httponly=True)

token = "abc123"
issue_cookie(response, token)
