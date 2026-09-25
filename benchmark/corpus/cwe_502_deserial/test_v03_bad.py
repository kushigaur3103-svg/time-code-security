import pickle, base64

def load_session(cookie):
    parts = {"raw": base64.b64decode(cookie)}
    return pickle.loads(parts["raw"])

cookie = input("cookie: ")
print(load_session(cookie))
