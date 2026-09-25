import ldap

query = input("q: ")
conn = ldap.initialize("ldap://internal")
conn.search("dc=corp", ldap.SCOPE_ONELEVEL, query)
