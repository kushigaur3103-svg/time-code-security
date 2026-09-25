from flask import session

def set_auth_token(token):
    session["user_id"] = token
