import json, base64

def load_session(cookie):
    parts = {"raw": base64.b64decode(cookie).decode("utf-8")}
    return json.loads(parts["raw"])

cookie = input("cookie: ")
print(load_session(cookie))
