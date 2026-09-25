from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com", "app.example.com"}

def login_redirect(next_url):
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        raise ValueError("Absolute URLs not allowed")
    print(f"Location: {next_url}")

next_url = input("next: ")
login_redirect(next_url)
