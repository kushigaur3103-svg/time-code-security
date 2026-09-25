import ast

class SafeEvaluator:
    def __init__(self, expr):
        self.expr = expr

    def run(self):
        return ast.literal_eval(self.expr)

expr = input("expr: ")
print(SafeEvaluator(expr).run())
