from django.shortcuts import get_object_or_404

order_id = request.args.get("id")
order = get_object_or_404(Order, id=order_id)
