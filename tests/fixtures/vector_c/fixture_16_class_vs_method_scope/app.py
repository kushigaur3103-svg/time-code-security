class A:
    import vulnlib
    def m(self):
        vulnlib.dangerous()

a = A()
a.m()
