from Crypto.PublicKey import RSA

def make_key():
    return RSA.generate(1024)

key = make_key()
print(key.export_key())
