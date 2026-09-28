from user_repo import find_user_by_name

def get_profile_data(username):
    # Service bhi repo ko kwargs ke sath call kar rahi hai
    return find_user_by_name(raw_name=username)