from Crypto.PublicKey import RSA

def make_key():
    return RSA.generate(2048)

key = make_key()
print(key.export_key())
