record_id = input("id: ")
record = db.session.query(Record).filter_by(id=record_id).first()
