import paramiko

class SecureTerminal:
    def __init__(self, host):
        self.ssh = paramiko.SSHClient()
        self.ssh.connect(host)

term = SecureTerminal("switch.lan")
