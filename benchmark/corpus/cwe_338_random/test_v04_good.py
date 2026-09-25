import secrets

class SessionManager:
    def __init__(self):
        self.session_secret = secrets.token_hex(32)

    def get_secret(self):
        return self.session_secret

mgr = SessionManager()
print(mgr.get_secret())
