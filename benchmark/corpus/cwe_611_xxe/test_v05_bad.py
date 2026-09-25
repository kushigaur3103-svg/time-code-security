from lxml import etree

def parse_xml(xml_data, strict):
    if strict:
        parser = etree.XMLParser(resolve_entities=True)
    else:
        parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(xml_data.encode(), parser)
    return root.tag

xml = input("xml: ")
print(parse_xml(xml, False))
