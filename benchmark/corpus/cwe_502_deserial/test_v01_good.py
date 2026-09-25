import json, base64

def load_session(cookie):
    return json.loads(base64.b64decode(cookie).decode())

cookie = input("cookie: ")
print(load_session(cookie))
