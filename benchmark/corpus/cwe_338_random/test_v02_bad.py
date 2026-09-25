import random

def make_secret():
    return str(random.random())

def issue_session_key():
    session_key = make_secret()
    return session_key

print(issue_session_key())
