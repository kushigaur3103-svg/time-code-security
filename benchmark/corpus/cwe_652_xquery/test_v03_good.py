from lxml import etree

def query_records(tree, rtype):
    return tree.xpath("//record[@type=$t]", t=rtype)

query_records(doc, input("t: "))
