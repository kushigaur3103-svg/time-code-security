import html as html_mod

def render_greeting(name):
    safe_name = html_mod.escape(name)
    return f"<h1>Hello, {safe_name}!</h1>"

name = input("name: ")
print(render_greeting(name))
