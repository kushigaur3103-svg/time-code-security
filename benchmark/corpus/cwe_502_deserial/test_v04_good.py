import json, base64

class SessionLoader:
    def __init__(self, cookie):
        self.data = base64.b64decode(cookie).decode("utf-8")

    def load(self):
        return json.loads(self.data)

cookie = input("cookie: ")
print(SessionLoader(cookie).load())
