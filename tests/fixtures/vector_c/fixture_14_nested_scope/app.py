def outer():
    import vulnlib
    def inner():
        vulnlib.dangerous()
    inner()

outer()
