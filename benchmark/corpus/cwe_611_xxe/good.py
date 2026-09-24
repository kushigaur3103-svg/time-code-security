from flask import request
import defusedxml.ElementTree as ET

def upload_catalog():
    xml_data = request.get_data()
    root = ET.fromstring(xml_data)
    return root.tag
