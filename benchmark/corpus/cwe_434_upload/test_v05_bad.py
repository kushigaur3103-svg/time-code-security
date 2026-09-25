filename = input("f: ")
if production:
    file.save("/var/uploads/" + filename)
else:
    file.save("/tmp/uploads/" + filename)
