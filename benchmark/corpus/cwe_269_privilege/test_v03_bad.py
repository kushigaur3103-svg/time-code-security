import os

class Worker:
    def run_as_root(self):
        os.setuid(0)
        self.serve()

Worker().run_as_root()
