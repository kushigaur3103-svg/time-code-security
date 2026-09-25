import random

def make_credentials():
    # Container flow: random value stored in dictionary under sensitive key
    return {
        "auth_secret": random.random(),
        "csrf_token": random.random(),
    }

print(make_credentials())
