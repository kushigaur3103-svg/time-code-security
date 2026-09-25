import defusedxml.ElementTree as ET

def parse_xml(xml_data):
    payloads = {"xml": xml_data}
    root = ET.fromstring(payloads["xml"])
    return root.tag

xml = input("xml: ")
print(parse_xml(xml))
