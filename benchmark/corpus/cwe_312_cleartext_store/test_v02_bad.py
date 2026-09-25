import json

password = input("p: ")
with open("creds.json", "w") as f:
    json.dump({"password": password}, f)
