import ftplib

client = ftplib.FTP_TLS()
client.connect("files.company.com", 21)
client.login("anonymous", "")
client.prot_p()
