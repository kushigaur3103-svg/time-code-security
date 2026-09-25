doc_id = request.args.get("id")
doc = Document.objects.get(pk=doc_id)
