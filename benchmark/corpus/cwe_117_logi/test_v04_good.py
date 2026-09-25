import logging

class Audit:
    def __init__(self, u):
        self.msg = sanitize_log_message(u)

    def report(self):
        logger = logging.getLogger("audit")
        logger.error(self.msg)

user = input("u: ")
Audit(user).report()
