import os

api_key = os.environ.get("API_KEY", "fallback")
print(api_key)
