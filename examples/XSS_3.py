# UNTRUSTED: request.args.get('username')
username = request.args.get('username')
html = "<script>var user = '%s';</script>" % username  # taint -> JS context -> XSS if quotes not escaped
return html
