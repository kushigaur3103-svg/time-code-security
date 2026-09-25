from lxml import etree

name = input("n: ")
tree = etree.parse("users.xml")
tree.xpath(f"//user[@name='{name}']")
