from ftplib import FTP

def download_file(server, filename):
    ftp = FTP(server)
    ftp.login()
    with open(filename, "wb") as f:
        ftp.retrbinary("RETR " + filename, f.write)
    ftp.quit()

download_file("ftp.debian.org", "release.txt")
