import jinja2

class TemplateRenderer:
    def __init__(self, name):
        self.tmpl_str = f"Hello {name}!"

    def render(self):
        return jinja2.Template(self.tmpl_str).render()

name = input("name: ")
print(TemplateRenderer(name).render())
