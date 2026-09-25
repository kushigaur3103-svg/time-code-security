import jinja2

def make_template(name):
    return f"Hello {name}!"

def render_greeting(name):
    tmpl_str = make_template(name)
    template = jinja2.Template(tmpl_str)
    return template.render()

name = input("name: ")
print(render_greeting(name))
