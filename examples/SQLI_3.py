# UNTRUSTED: request.get_json().get('q')
q = request.get_json().get('q')
sql = "SELECT * FROM items WHERE desc LIKE '%{}%'".format(q)  # taint -> SQL sink
cursor.execute(sql)
