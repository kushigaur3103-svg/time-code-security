from urllib.parse import urlparse

def login_redirect(next_url):
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        next_url = "/"
    print(f"Location: {next_url}")

next_url = input("next: ")
login_redirect(next_url)
