import rsa

def make_key(legacy):
    if legacy:
        return rsa.generate_private_key(1024, 65537)
    return rsa.generate_private_key(2048, 65537)

key = make_key(True)
print(key)
