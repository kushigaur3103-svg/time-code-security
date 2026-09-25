from Crypto.PublicKey import RSA

def make_key():
    bits = 1024
    return RSA.generate(bits)

key = make_key()
print(key.export_key())
