def func_a():
    import vulnlib as v
    v.dangerous()

def func_b():
    import safe_lib as v
    v.dangerous()

func_a()
func_b()
