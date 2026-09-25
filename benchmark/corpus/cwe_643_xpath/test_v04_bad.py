from lxml import etree

class UserLookup:
    def __init__(self, u):
        self.query = f"//user[@name='{u}']"

    def run(self):
        tree = etree.parse("users.xml")
        return tree.xpath(self.query)

name = input("n: ")
UserLookup(name).run()
