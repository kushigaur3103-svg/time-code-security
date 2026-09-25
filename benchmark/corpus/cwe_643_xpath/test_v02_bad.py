from lxml import etree

def build_xpath(u):
    return f"//user[@name='{u}']"

tree = etree.parse("users.xml")
name = input("n: ")
tree.xpath(build_xpath(name))
