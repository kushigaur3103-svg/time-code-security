def grant(user):
    if user == "admin":
        return "granted"
    return "denied"

grant(input("u: "))
