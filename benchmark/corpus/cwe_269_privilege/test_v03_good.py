import os

class Worker:
    def drop_privileges(self, worker_uid):
        if os.geteuid() == 0:
            os.setuid(worker_uid)
        self.serve()

Worker().drop_privileges(1001)
