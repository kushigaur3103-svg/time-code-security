import requests

def call_api(url):
    options = {"verify": True, "timeout": 10}
    return requests.get(url, **options)

resp = call_api("https://api.internal.example.com/data")
print(resp.status_code)
