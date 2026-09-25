from ldap3 import Connection
from ldap3.utils.conv import escape_filter_chars

class DirectoryService:
    def __init__(self, conn):
        self.conn = conn

    def lookup(self, mail):
        filt = f"(mail={escape_filter_chars(mail)})"
        self.conn.search("dc=org", filt)

service = DirectoryService(conn)
service.lookup(input("mail: "))
