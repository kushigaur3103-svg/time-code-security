def func_a():
    import vulnlib
    vulnlib.dangerous()

def func_b():
    vulnlib.dangerous()

func_a()
func_b()
