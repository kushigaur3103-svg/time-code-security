user = input("u: ")
if user in {"alice", "bob"}:
    collection.find({"username": user})
