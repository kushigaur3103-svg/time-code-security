import vulnlib

def helper():
    vulnlib.dangerous()

def wrapper():
    helper()

def main():
    wrapper()

main()
