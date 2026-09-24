from flask import request, redirect
import urllib.parse

def is_safe_redirect_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc == "company.com" and parsed.scheme in ("https",)

def auth_callback():
    target = request.args.get("next")
    if is_safe_redirect_url(target):
        return redirect(target)
    return redirect("/home")
