user = input("u: ")
collection.find(sanitize_nosql_query({"username": user}))
