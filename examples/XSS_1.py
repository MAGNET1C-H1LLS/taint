# UNTRUSTED: request.args.get('msg')
msg = request.args.get('msg')
return f"<div>User wrote: {msg}</div>"  # taint -> HTML sink
