from lxml import etree

item_id = input("id: ")
root = etree.fromstring(xml_text)
nodes = root.xpath("//item[@id=$id]", id=item_id)
