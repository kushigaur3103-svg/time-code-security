import jinja2

def render_greeting(name):
    template = jinja2.Template(f"Hello {name}!")
    return template.render()

name = input("name: ")
print(render_greeting(name))
