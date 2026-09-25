class XMLQueryService:
    def __init__(self, root):
        self.root = root

    def search_doc(self, tag):
        return self.root.xpath(f"//{tag}")

service = XMLQueryService(tree)
service.search_doc(input("tag: "))
