import logging

class Audit:
    def __init__(self, u):
        self.msg = u

    def report(self):
        logger = logging.getLogger("audit")
        logger.warning(self.msg)

user = input("u: ")
Audit(user).report()
