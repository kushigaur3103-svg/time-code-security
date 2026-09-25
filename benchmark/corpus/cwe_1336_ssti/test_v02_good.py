import jinja2

def render_greeting(name):
    template = jinja2.Template("Hello {{ name }}!")
    return template.render(name=name)

name = input("name: ")
print(render_greeting(name))
