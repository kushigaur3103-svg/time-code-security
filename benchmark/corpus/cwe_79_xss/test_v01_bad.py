def render_greeting(name):
    return f"<h1>Hello, {name}!</h1>"

name = input("name: ")
print(render_greeting(name))
