import rsa

key = rsa.generate_private_key(2048, 65537)
print(key)
