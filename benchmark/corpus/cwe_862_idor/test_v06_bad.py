from flask_login import current_user

order_id = request.args.get("id")
order = Order.query.get(order_id)
