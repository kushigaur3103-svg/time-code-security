from ftplib import FTP_TLS

def download_file(server, filename):
    ftps = FTP_TLS(server)
    ftps.login()
    ftps.prot_p()
    with open(filename, "wb") as f:
        ftps.retrbinary("RETR " + filename, f.write)
    ftps.quit()

download_file("ftp.debian.org", "release.txt")
