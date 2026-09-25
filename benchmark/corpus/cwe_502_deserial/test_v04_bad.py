import pickle, base64

class SessionLoader:
    def __init__(self, cookie):
        self.raw = base64.b64decode(cookie)

    def load(self):
        return pickle.loads(self.raw)

cookie = input("cookie: ")
print(SessionLoader(cookie).load())
