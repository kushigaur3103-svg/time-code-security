import defusedxml.ElementTree as ET

def parse_xml(xml_data, strict):
    if strict:
        root = ET.fromstring(xml_data)
    else:
        root = ET.fromstring(xml_data)
    return root.tag

xml = input("xml: ")
print(parse_xml(xml, False))
