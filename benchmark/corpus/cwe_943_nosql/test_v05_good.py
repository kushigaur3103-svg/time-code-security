def lookup(user, strict):
    safe = sanitize_nosql_input(user)
    if strict:
        collection.find({"username": safe})
    else:
        collection.find_one({"username": safe})

user = input("u: ")
lookup(user, True)
