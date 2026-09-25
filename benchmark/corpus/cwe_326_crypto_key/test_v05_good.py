from Crypto.PublicKey import RSA

def make_key(high_grade):
    if high_grade:
        return RSA.generate(4096)
    return RSA.generate(2048)

key = make_key(True)
print(key.export_key())
