# UNTRUSTED: request.headers.get('return_to')
to = request.headers.get('return_to')
from flask import Response
resp = Response("", status=302)
resp.headers['Location'] = to  # taint -> redirect sink
return resp
