def complete_login(sess, user_obj):
    if valid_user(user_obj):
        sess.regenerate_id()
        sess["user"] = user_obj.username
