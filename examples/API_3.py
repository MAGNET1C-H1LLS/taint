# UNTRUSTED: request.json['values']
vals = request.json.get('values', [])
vals_escaped = ["'{}'".format(v) for v in vals]  # naive wrapping
query = "INSERT INTO t (c) VALUES (" + ",".join(vals_escaped) + ")"  # taint -> SQL sink
cursor.execute(query)
