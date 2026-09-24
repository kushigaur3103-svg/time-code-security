from flask import request
import markupsafe

def show_profile():
    name = request.args.get("name")
    return markupsafe.Markup(f"<b>Hello {name}</b>")
