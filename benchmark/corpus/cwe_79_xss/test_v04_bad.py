class PageRenderer:
    def __init__(self, name):
        self.name = name

    def render(self):
        return f"<h1>{self.name}</h1>"

name = input("name: ")
print(PageRenderer(name).render())
