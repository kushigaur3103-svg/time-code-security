class DocumentView:
    def __init__(self, doc_id):
        self.doc_id = doc_id

    def view(self):
        return Document.objects.get(pk=self.doc_id)

DocumentView(request.args.get("id")).view()
