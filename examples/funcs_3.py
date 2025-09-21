# UNTRUSTED: request.args.get('id')
def a(x): return x
def b(y): return a(y)
def c(z): return b(z)
val = c(request.args.get('id'))
cursor.execute("SELECT * FROM t WHERE id=%s" % val)

# UNTRUSTED: request.form.get('note')
def weak(x): return x
def wrapper(a): return weak(a)
def logit(m):
    import logging
    logging.error("note: " + m)
n = wrapper(request.form.get('note'))
logit(n)


# UNTRUSTED: request.get_json().get('v')
def ex(x): return x.get('v')
def render(t): return "<b>%s</b>" % t
title = ex(request.get_json())
out = render(title)
return out
