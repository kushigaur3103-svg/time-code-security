import lxml.etree

name = input("n: ")
lxml.etree.XPath(f"//user[@name='{name}']")
