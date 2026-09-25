import requests

def call_api(url, dev_mode):
    if dev_mode:
        return requests.get(url, verify=False)
    else:
        return requests.get(url, verify=False)

resp = call_api("https://api.internal.example.com/data", True)
print(resp.status_code)
