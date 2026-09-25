def build_query(u):
    return {"username": u}

user = input("u: ")
query = build_query(user)
collection.find(query)
