from defusedxml.sax import parseString
from xml.sax import ContentHandler

data = input("xml: ")
handler = ContentHandler()
parseString(data, handler)
