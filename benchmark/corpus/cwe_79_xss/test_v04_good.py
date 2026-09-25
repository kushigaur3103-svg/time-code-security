import html as html_mod

class PageRenderer:
    def __init__(self, name):
        self.snippet = f"<h1>{html_mod.escape(name)}</h1>"

    def render(self):
        return f"<html><body>{self.snippet}</body></html>"

name = input("name: ")
print(PageRenderer(name).render())
