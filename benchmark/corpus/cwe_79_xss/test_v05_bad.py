def render_user(name, is_admin):
    if is_admin:
        return f"<h1>Admin: {name}</h1>"
    else:
        return f"<h1>User: {name}</h1>"

name = input("name: ")
print(render_user(name, False))
