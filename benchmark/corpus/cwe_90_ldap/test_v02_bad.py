from ldap3 import Server, Connection

username = input("u: ")
password = input("p: ")
query = "(&(uid=" + username + ")(userPassword=" + password + "))"
conn = Connection(Server("ldap://example.com"))
conn.search("dc=example,dc=com", query)
