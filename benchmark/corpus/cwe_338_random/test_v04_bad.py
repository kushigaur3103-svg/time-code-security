import random

class SessionManager:
    def __init__(self):
        self.session_secret = random.random()

    def get_secret(self):
        return self.session_secret

mgr = SessionManager()
print(mgr.get_secret())
