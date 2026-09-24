from flask import request
import xml.etree.ElementTree as ET

def upload_catalog():
    xml_data = request.get_data()
    root = ET.fromstring(xml_data)
    return root.tag
