import pickle, base64

def load_session(cookie):
    return pickle.loads(base64.b64decode(cookie))

cookie = input("cookie: ")
print(load_session(cookie))
