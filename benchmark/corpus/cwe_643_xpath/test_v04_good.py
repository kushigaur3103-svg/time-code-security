from lxml import etree

class UserLookup:
    def __init__(self, name):
        self.query = "//user[@name=$n]"
        self.name = name

    def run(self):
        tree = etree.parse("users.xml")
        return tree.xpath(self.query, name=self.name)

name = input("n: ")
UserLookup(name).run()
