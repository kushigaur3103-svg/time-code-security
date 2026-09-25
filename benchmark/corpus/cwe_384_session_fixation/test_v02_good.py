def authenticate_user(request, user):
    request.session.cycle_key()
    request.session["user_id"] = user.id
    return "ok"
