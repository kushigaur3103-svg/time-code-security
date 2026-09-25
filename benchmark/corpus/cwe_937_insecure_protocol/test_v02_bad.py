from ftplib import FTP

ftp = FTP("ftp.example.com")
ftp.login("user", "pass")
ftp.retrlines("LIST")
ftp.quit()
