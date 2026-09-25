from flask import abort

doc_id = input("id: ")
doc = Document.objects.get(pk=doc_id)
if doc.owner_id != request.user.id:
    abort(403)
