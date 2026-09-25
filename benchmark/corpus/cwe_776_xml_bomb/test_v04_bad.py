from xml.sax import parseString, ContentHandler

data = input("xml: ")
handler = ContentHandler()
parseString(data, handler)
