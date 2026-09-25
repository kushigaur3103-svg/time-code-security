import requests

def send_creds(host, user, secret):
    url = f"https://{host}/authenticate"
    return requests.post(url, auth=(user, secret))

send_creds("secure.org", "alice", input("s: "))
