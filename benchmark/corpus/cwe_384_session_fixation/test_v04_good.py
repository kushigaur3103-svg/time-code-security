def on_login(req, uid):
    req.session.cycle_key()
    req.session["uid"] = uid
