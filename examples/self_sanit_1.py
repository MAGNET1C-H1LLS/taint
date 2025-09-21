# UNTRUSTED: request.args.get('url')
from urllib.parse import urlparse

def sanitize_url(s):
    p = urlparse(s)
    if p.scheme not in ("https",) or not p.netloc:
        raise ValueError("bad")
    return s

try:
    safe = sanitize_url(request.args.get('url'))
    return redirect(safe)  # safe redirect
except Exception:
    abort(400)
