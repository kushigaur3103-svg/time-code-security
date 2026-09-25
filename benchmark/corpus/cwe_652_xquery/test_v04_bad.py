from lxml import etree

category = input("c: ")
q = "//book[category='{}']".format(category)
tree.xpath(q)
