# UNTRUSTED: request.get_json()['items']
items = request.get_json().get('items')
from flask import jsonify
return jsonify({"items": items})  # taint -> API response sink (client-side rendering may XSS)
