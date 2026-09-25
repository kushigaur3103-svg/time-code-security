class DocumentView:
    def __init__(self, doc_id, user):
        self.doc_id = doc_id
        self.user = user

    def view(self):
        return Document.objects.get(pk=self.doc_id, owner=self.user)

DocumentView(request.args.get("id"), request.user).view()
