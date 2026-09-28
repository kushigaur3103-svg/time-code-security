from user_repo import find_user_by_name

def get_profile_data(username):
    # Pass-through: Parameter username sink function mein pass ho raha hai
    return find_user_by_name(username)