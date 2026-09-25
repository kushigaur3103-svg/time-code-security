import requests

def call_api(url):
    return requests.get(url, verify=True)

resp = call_api("https://api.internal.example.com/data")
print(resp.status_code)
