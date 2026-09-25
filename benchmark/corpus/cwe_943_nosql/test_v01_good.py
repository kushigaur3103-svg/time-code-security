user = input("u: ")
safe = sanitize_nosql_input(user)
collection.find({"username": safe})
