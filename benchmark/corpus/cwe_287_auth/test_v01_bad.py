def authenticate(username, password):
    if password == "admin123":
        return True
    return False

authenticate(input("u: "), input("p: "))
