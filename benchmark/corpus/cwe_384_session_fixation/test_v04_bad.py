def on_login(req, uid):
    req.session.flush()
    # But then old session used elsewhere
    session["uid"] = uid
