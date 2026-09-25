import random

def generate_auth_token():
    auth_token = str(random.random())
    return auth_token

print(generate_auth_token())
