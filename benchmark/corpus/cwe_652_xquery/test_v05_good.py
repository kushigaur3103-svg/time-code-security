class XMLQueryService:
    def __init__(self, root):
        self.root = root

    def search_doc(self, tag):
        return self.root.xpath("//*[local-name()=$tag]", tag=tag)

service = XMLQueryService(tree)
service.search_doc(input("tag: "))
