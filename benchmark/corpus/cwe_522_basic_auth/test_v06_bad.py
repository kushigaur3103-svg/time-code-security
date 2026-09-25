import requests

def send_creds(host, user, secret):
    url = f"http://{host}/authenticate"
    return requests.post(url, auth=(user, secret))

send_creds("insecure.org", "alice", input("s: "))
