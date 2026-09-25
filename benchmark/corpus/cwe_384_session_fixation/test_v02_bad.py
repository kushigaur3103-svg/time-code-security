def authenticate_user(request, user):
    request.session["user_id"] = user.id
    return "ok"
