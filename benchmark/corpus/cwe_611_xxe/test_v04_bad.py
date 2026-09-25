from lxml import etree

class XmlProcessor:
    def __init__(self, xml_data):
        self.payload = xml_data.encode()

    def parse(self):
        root = etree.fromstring(self.payload)
        return root.tag

xml = input("xml: ")
print(XmlProcessor(xml).parse())
