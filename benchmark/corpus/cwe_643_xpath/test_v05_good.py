from lxml import etree

def lookup(name, strict):
    tree = etree.parse("users.xml")
    if strict:
        return tree.xpath("//user[@name=$n]", name=name)
    return tree.xpath("//user[@id=$i]", id=name)

name = input("n: ")
lookup(name, True)
