import requests

def call_api(url):
    # Container flow: options dict with verify=False unpacked into get()
    options = {"verify": False}
    return requests.get(url, **options)

resp = call_api("https://api.internal.example.com/data")
print(resp.status_code)
