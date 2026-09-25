import defusedxml.ElementTree as ET

def process_file(path):
    tree = ET.parse(path)
    return tree.getroot()

process_file("config.xml")
