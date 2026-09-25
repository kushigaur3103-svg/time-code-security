import defusedxml.ElementTree as ET

class XmlProcessor:
    def __init__(self, xml_data):
        self.payload = xml_data

    def parse(self):
        root = ET.fromstring(self.payload)
        return root.tag

xml = input("xml: ")
print(XmlProcessor(xml).parse())
