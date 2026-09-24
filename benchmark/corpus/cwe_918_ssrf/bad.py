from flask import request
import requests

def fetch_webhook():
    webhook_url = request.args.get("webhook")
    response = requests.get(webhook_url)
    return response.text
