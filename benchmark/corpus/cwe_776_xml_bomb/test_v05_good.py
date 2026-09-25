from defusedxml.ElementTree import fromstring

class XMLParserHandler:
    def __init__(self, raw):
        self.raw = raw

    def parse(self):
        return fromstring(self.raw)

handler = XMLParserHandler(input("data: "))
handler.parse()
