import random

def create_api_credentials():
    token = random.randint(100000, 999999)
    session_key = random.choice("0123456789abcdef")
    return token, session_key
