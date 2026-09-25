import urllib.request

creds = "user=alice&password=secret"
urllib.request.urlopen("http://login.example.com/auth", data=creds.encode())
