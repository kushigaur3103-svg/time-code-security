import requests

def query_internal_api():
    return requests.get("https://api.internal.com", verify=False)
