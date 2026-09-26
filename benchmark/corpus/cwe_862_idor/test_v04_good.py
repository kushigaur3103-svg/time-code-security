invoice_id = request.args.get("id")
invoice = db.session.query(Invoice).filter_by(id=invoice_id, user_id=user.id).first()
