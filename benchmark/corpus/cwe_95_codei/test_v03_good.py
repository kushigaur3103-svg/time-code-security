import ast

def run_expr(user_input):
    ops = {"expr": user_input}
    return ast.literal_eval(ops["expr"])

user_input = input("expr: ")
print(run_expr(user_input))
