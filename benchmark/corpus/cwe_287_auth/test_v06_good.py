def login(username, password):
    user = db.authenticate(username, password)
    if not user:
        return None
    session["user_id"] = user.id
    return user
