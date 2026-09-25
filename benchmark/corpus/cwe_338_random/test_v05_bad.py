import random

def issue_token(for_admin):
    if for_admin:
        auth_token = str(random.randint(0, 999999))
    else:
        auth_token = str(random.randint(0, 999999))
    return auth_token

print(issue_token(False))
