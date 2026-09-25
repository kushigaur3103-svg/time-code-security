from lxml import etree

name = input("n: ")
q = {"xpath": f"//user[@name='{name}']"}
tree = etree.parse("users.xml")
tree.xpath(q["xpath"])
