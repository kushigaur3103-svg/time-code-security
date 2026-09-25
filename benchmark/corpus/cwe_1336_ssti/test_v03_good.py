import jinja2

def render_greeting(name):
    parts = {"tmpl": "Welcome {{ name }}!"}
    template = jinja2.Template(parts["tmpl"])
    return template.render(name=name)

name = input("name: ")
print(render_greeting(name))
