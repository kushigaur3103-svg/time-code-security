from lxml import etree

val = input("v: ")
expr = f"/catalog/cd[price < {val}]"
tree.xpath(expr)
