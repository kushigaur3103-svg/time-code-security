from flask import session, abort

def view_profile():
    if not session.get("user_id"):
        abort(401)
    return "profile"
