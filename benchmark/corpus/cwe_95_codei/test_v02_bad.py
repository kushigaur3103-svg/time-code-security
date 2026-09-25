def run_code(code):
    exec(code)

def process_input(user_input):
    run_code(user_input)

user_input = input("code: ")
process_input(user_input)
