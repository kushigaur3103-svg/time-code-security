import urllib.request
import base64

auth_str = base64.b64encode(b"alice:pass").decode()
req = urllib.request.Request("https://example.com/auth")
req.add_header("Authorization", "Basic " + auth_str)
urllib.request.urlopen(req)
