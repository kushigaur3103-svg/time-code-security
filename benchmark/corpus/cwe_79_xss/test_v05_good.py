import html as html_mod

def render_user(name, is_admin):
    safe = html_mod.escape(name)
    if is_admin:
        banner = f"<h1>Admin: {safe}</h1>"
    else:
        banner = f"<h1>User: {safe}</h1>"
    return banner

name = input("name: ")
print(render_user(name, False))
