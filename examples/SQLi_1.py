# UNTRUSTED: request.args.get('id')
id = request.args.get('id')
query = "SELECT * FROM users WHERE id = %s" % id  # taint -> SQL sink (string interpolation)
cursor.execute(query)
