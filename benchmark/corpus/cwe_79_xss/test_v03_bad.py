def render_page(name):
    parts = {"header": name, "tag": "h1"}
    return f"<{parts['tag']}>{parts['header']}</{parts['tag']}>"

name = input("name: ")
print(render_page(name))
