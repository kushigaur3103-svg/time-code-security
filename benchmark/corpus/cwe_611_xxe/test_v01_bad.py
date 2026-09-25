from lxml import etree

def parse_xml(xml_data):
    root = etree.fromstring(xml_data.encode())
    return root.tag

xml = input("xml: ")
print(parse_xml(xml))
