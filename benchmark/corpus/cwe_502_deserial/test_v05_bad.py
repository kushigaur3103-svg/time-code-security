import pickle, json, base64

def load_session(cookie, legacy):
    if legacy:
        return pickle.loads(base64.b64decode(cookie))
    else:
        return pickle.loads(base64.b64decode(cookie))

cookie = input("cookie: ")
print(load_session(cookie, True))
