from lxml import etree

def decode_xml(raw):
    return raw.encode()

def parse_xml(xml_data):
    data = decode_xml(xml_data)
    root = etree.fromstring(data)
    return root.tag

xml = input("xml: ")
print(parse_xml(xml))
