from lxml import etree

def query_records(tree, rtype):
    query = "//record[@type='%s']" % rtype
    return tree.xpath(query)

query_records(doc, input("t: "))
