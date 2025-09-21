# UNTRUSTED: request.form['tok']
def read(req):
    return req.form['tok']

def passthrough(f):
    return f()  # taint через callback

def sink(val):
    cursor.execute("INSERT INTO tokens(val) VALUES ('%s')" % val)  # sink

sink(passthrough(lambda: read(request)))
