class UserQuery:
    def __init__(self, u):
        self.query = {"username": u}

    def run(self):
        collection.find(self.query)

user = input("u: ")
UserQuery(user).run()
