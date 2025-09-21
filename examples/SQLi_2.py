# UNTRUSTED: request.values.get('name')
name = request.values.get('name')
query = "SELECT * FROM products WHERE name = '" + name + "'"  # taint -> SQL sink
cursor.execute(query)
