import jinja2

def render_greeting(name, formal):
    if formal:
        tmpl = f"Dear {name},"
    else:
        tmpl = f"Hi {name}!"
    return jinja2.Template(tmpl).render()

name = input("name: ")
print(render_greeting(name, False))
