from flask import request
import jinja2

def render_greeting():
    name = request.args.get("name")
    template = jinja2.Template("Hello {{ name }}!")
    return template.render(name=name)
