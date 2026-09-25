import ast

ALLOWED = {"print", "len"}

def process_input(user_input):
    tree = ast.parse(user_input, mode="eval")
    result = ast.literal_eval(tree)
    print(result)

user_input = input("expr: ")
process_input(user_input)
