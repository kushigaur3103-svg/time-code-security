import jinja2

class TemplateRenderer:
    def __init__(self, name):
        self.name = name

    def render(self):
        return jinja2.Template("Hello {{ name }}!").render(name=self.name)

name = input("name: ")
print(TemplateRenderer(name).render())
