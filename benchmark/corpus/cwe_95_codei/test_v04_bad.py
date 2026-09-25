class Executor:
    def __init__(self, code):
        self.code = code

    def run(self):
        exec(self.code)

code = input("code: ")
Executor(code).run()
