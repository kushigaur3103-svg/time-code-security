from flask import request
import html
import markupsafe

def show_profile():
    name = request.args.get("name")
    safe_name = html.escape(name)
    return markupsafe.Markup(f"<b>Hello {safe_name}</b>")
