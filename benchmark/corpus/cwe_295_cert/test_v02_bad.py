import requests

def get_session():
    # Multi-hop: session configured with SSL verification disabled
    s = requests.Session()
    s.verify = False
    return s

def call_api(url):
    session = get_session()
    return session.get(url)

resp = call_api("https://api.internal.example.com/data")
print(resp.status_code)
