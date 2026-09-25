from lxml import etree

def parse_xml(xml_data):
    payloads = {"xml": xml_data.encode()}
    root = etree.fromstring(payloads["xml"])
    return root.tag

xml = input("xml: ")
print(parse_xml(xml))
