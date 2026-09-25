from flask import session

def login(user):
    session["user_id"] = user.id
    return "logged in"
