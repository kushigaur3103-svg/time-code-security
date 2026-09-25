import ftplib

client = ftplib.FTP()
client.connect("files.company.com", 21)
client.login("anonymous", "")
