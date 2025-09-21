# UNTRUSTED: request.args['id']
def get_param(req):
    return req.args['id']

def transform(x):
    return x.strip()  # не удаляет SQL-символы

def use_param(v):
    cursor.execute("DELETE FROM sessions WHERE id = %s" % v)  # sink

use_param(transform(get_param(request)))
