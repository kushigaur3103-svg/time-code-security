from lxml import etree

def lookup(name, strict):
    tree = etree.parse("users.xml")
    if strict:
        return tree.xpath(f"//user[@name='{name}']")
    return tree.xpath(f"//user[contains(@name, '{name}')]")

name = input("n: ")
lookup(name, True)
