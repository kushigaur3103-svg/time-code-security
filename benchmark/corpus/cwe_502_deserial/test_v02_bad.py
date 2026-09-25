import pickle, base64

def decode_payload(raw):
    return base64.b64decode(raw)

def load_session(cookie):
    data = decode_payload(cookie)
    return pickle.loads(data)

cookie = input("cookie: ")
print(load_session(cookie))
