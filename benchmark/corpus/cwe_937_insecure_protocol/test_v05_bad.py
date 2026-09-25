import telnetlib

class LegacyTerminal:
    def __init__(self, host):
        self.session = telnetlib.Telnet(host)

term = LegacyTerminal("switch.lan")
