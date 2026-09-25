import html as html_mod

def wrap_tag(tag, content):
    return f"<{tag}>{html_mod.escape(content)}</{tag}>"

def render_greeting(name):
    return wrap_tag("h1", name)

name = input("name: ")
print(render_greeting(name))
