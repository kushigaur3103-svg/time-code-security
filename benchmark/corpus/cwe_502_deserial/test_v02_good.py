import json, base64

def load_session(cookie):
    data = base64.b64decode(cookie).decode("utf-8")
    return json.loads(data)

cookie = input("cookie: ")
print(load_session(cookie))
