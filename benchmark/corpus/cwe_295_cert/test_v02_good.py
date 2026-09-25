import requests

def build_session():
    s = requests.Session()
    s.verify = True
    return s

def call_api(url):
    session = build_session()
    return session.get(url)

resp = call_api("https://api.internal.example.com/data")
print(resp.status_code)
