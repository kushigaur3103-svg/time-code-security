from flask import session

def login(user):
    session.clear()
    session["user_id"] = user.id
    return "logged in"
