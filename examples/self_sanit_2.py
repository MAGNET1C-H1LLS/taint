# UNTRUSTED: request.form.get('name')
def weak_clean(s):
    bad = ["select", "insert", "--"]
    for b in bad:
        s = s.replace(b, "")
    return s

name = weak_clean(request.form.get('name'))
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)  # taint -> SQL sink
