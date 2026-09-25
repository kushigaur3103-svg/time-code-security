import json, base64

def load_session(cookie, legacy):
    data = base64.b64decode(cookie).decode("utf-8")
    if legacy:
        return json.loads(data)
    else:
        return json.loads(data)

cookie = input("cookie: ")
print(load_session(cookie, True))
