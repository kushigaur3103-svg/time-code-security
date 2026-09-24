from flask import request
import urllib.parse
import requests

def is_safe_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in ("https",) and parsed.netloc in ("api.internal.net", "hooks.internal.net")

def fetch_webhook():
    webhook_url = request.args.get("webhook")
    if is_safe_url(webhook_url):
        response = requests.get(webhook_url)
        return response.text
    return "Blocked URL"
