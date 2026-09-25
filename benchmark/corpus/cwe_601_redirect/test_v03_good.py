from urllib.parse import urlparse

def login_redirect(next_url):
    parsed = urlparse(next_url)
    safe_url = next_url if not (parsed.scheme or parsed.netloc) else "/"
    routes = {"target": safe_url}
    print(f"Location: {routes['target']}")

next_url = input("next: ")
login_redirect(next_url)
