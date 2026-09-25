from lxml import etree

user_input = input("n: ")
q = {"xpath": "//user[@name=$n]"}
tree = etree.parse("users.xml")
tree.xpath(q["xpath"], name=user_input)
