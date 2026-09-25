import xml.etree.ElementTree as ET

class XMLParserHandler:
    def __init__(self, raw):
        self.raw = raw

    def parse(self):
        return ET.fromstring(self.raw)

handler = XMLParserHandler(input("data: "))
handler.parse()
