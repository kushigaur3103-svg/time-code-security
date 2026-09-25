import telnetlib

host = "router.local"
tn = telnetlib.Telnet(host, 23)
tn.write(b"admin\n")
