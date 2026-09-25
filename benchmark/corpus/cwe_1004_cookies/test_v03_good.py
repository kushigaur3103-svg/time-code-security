class SessionHandler:
    def __init__(self):
        self.response = FlaskResponse()

    def start(self, token):
        self.response.set_cookie("sid", token, httponly=True, secure=True)

handler = SessionHandler()
handler.start("abc123")
