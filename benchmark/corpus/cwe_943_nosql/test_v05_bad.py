user = input("u: ")
if strict:
    collection.find({"username": user, "$where": f"this.x == '{user}'"})
else:
    collection.find_one({"username": user})
