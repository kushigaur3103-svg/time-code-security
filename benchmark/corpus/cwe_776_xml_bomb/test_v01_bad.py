import xml.etree.ElementTree as ET

xml_data = input("xml: ")
root = ET.fromstring(xml_data)
print(root.tag)
