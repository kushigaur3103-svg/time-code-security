order_id = request.args.get("id")
if internal:
    order = Order.query.get(order_id)
else:
    order = Order.query.get(int(order_id))
