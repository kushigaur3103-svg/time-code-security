from lxml import etree

user_input = input("n: ")
tree = etree.parse("users.xml")
tree.xpath("//user[@name=$n]", name=user_input)
