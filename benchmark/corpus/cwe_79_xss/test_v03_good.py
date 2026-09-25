import html as html_mod

def render_page(name):
    parts = {"header": f"<h1>{html_mod.escape(name)}</h1>", "body": "<p>Welcome</p>"}
    return parts["header"] + parts["body"]

name = input("name: ")
print(render_page(name))
