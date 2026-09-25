import jinja2

def render_greeting(name, formal):
    if formal:
        tmpl = "Dear {{ name }},"
    else:
        tmpl = "Hi {{ name }}!"
    return jinja2.Template(tmpl).render(name=name)

name = input("name: ")
print(render_greeting(name, False))
