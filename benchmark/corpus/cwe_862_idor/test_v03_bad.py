invoice_id = input("id: ")
invoice = db.session.query(Invoice).filter_by(id=invoice_id).first()
