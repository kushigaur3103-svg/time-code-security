def complete_login(sess, user_obj):
    if valid_user(user_obj):
        sess["user"] = user_obj.username
