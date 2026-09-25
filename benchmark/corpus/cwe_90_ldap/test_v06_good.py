import ldap

STATIC_FILTER = "(objectClass=organizationalUnit)"
conn = ldap.initialize("ldap://internal")
conn.search("dc=corp", ldap.SCOPE_ONELEVEL, STATIC_FILTER)
