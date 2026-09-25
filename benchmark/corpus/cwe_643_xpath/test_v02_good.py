from lxml import etree

query = etree.XPath("//user[@name=$n]")
tree = etree.parse("users.xml")
user_input = input("n: ")
tree.xpath(query, name=user_input)
