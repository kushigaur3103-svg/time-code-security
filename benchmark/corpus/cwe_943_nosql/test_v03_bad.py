user = input("u: ")
query = {"$where": f"this.name == '{user}'"}
collection.find(query)
