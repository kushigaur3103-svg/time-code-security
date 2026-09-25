user = input("u: ")
collection.update_many({"username": user}, {"$set": {"active": True}})
