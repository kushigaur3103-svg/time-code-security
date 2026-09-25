from lxml import etree

name = input("n: ")
tree = etree.parse("users.xml")
res = tree.xpath(f"//user[name='{name}']")
