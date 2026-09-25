import json

username = input("u: ")
role = input("r: ")
with open("profile.json", "w") as f:
    json.dump({"username": username, "role": role}, f)
