from ldap3 import Connection

class DirectoryService:
    def __init__(self, conn):
        self.conn = conn

    def lookup(self, mail):
        filt = f"(mail={mail})"
        self.conn.search("dc=org", filt)

service = DirectoryService(conn)
service.lookup(input("mail: "))
