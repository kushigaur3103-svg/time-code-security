MAX_SIZE = 1048576
with open("huge_data.bin", "rb") as f:
    payload = f.read(MAX_SIZE)
