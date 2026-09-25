record_id = request.args.get("id")
record = db.session.query(Record).filter_by(id=record_id, user_id=user.id).first()
