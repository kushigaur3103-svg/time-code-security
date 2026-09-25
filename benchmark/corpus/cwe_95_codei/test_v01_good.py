import ast

def calculate(expr):
    return ast.literal_eval(expr)

expr = input("expr: ")
print(calculate(expr))
