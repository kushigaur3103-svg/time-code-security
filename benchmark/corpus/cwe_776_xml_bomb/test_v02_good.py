from defusedxml import minidom

payload = request.data
doc = minidom.parseString(payload)
print(doc.toxml())
