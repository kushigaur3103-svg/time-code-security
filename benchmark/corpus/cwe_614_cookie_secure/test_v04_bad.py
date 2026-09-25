class SessionHandler:
    def __init__(self, token):
        self.token = token

    def start(self):
        self.response.set_cookie("sid", self.token, httponly=True)

handler = SessionHandler("abc123")
handler.start()
