class AuthController:
    def __init__(self, session):
        self.session = session

    def sign_in(self, username):
        self.session.regenerate()
        self.session["username"] = username
