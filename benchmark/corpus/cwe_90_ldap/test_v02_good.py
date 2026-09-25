from ldap3 import Server, Connection
from ldap3.utils.conv import escape_filter_chars

username = input("u: ")
password = input("p: ")
query = "(&(uid=" + escape_filter_chars(username) + ")(userPassword=" + escape_filter_chars(password) + "))"
conn = Connection(Server("ldap://example.com"))
conn.search("dc=example,dc=com", query)
