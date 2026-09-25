from ftplib import FTP_TLS

ftps = FTP_TLS("ftp.example.com")
ftps.login("user", "pass")
ftps.prot_p()
ftps.retrlines("LIST")
ftps.quit()
